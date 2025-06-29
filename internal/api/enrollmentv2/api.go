//go:generate oapi-codegen -config=./config.yml -package=enrollmentv2 -o=./api_gen.go ./swagger.yml
package enrollmentv2

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
	"github.com/luikyv/mock-bank/internal/account"
	"github.com/luikyv/mock-bank/internal/api"
	"github.com/luikyv/mock-bank/internal/api/middleware"
	"github.com/luikyv/mock-bank/internal/autopayment"
	"github.com/luikyv/mock-bank/internal/bank"
	"github.com/luikyv/mock-bank/internal/consent"
	"github.com/luikyv/mock-bank/internal/enrollment"
	"github.com/luikyv/mock-bank/internal/errorutil"
	"github.com/luikyv/mock-bank/internal/idempotency"
	"github.com/luikyv/mock-bank/internal/payment"
	"github.com/luikyv/mock-bank/internal/timeutil"
)

var _ StrictServerInterface = Server{}

type Server struct {
	baseURL            string
	service            enrollment.Service
	idempotencyService idempotency.Service
	op                 *provider.Provider
	keystoreHost       string
	orgID              string
	signer             crypto.Signer
}

func NewServer(
	host string,
	service enrollment.Service,
	idempotencyService idempotency.Service,
	op *provider.Provider,
	keystoreHost string,
	orgID string,
	signer crypto.Signer,
) Server {
	return Server{
		baseURL:            host + "/open-banking/enrollments/v2",
		service:            service,
		idempotencyService: idempotencyService,
		op:                 op,
		keystoreHost:       keystoreHost,
		orgID:              orgID,
		signer:             signer,
	}
}

func (s Server) RegisterRoutes(mux *http.ServeMux) {
	enrollmentMux := http.NewServeMux()

	jwtMiddleware := middleware.JWT(s.baseURL, s.orgID, s.keystoreHost, s.signer)
	idempotencyMiddleware := middleware.Idempotency(s.idempotencyService)
	clientCredentialsAuthMiddleware := middleware.Auth(s.op, goidc.GrantClientCredentials, payment.Scope)
	authCodeAuthMiddleware := middleware.Auth(s.op, goidc.GrantAuthorizationCode, goidc.ScopeOpenID, enrollment.ScopeID, enrollment.ScopeConsent, payment.Scope)
	swaggerMiddleware, _ := middleware.Swagger(GetSwagger, func(err error) string {
		var schemaErr *openapi3.SchemaError
		if errors.As(err, &schemaErr) && schemaErr.SchemaField == "required" {
			return "PARAMETRO_NAO_INFORMADO"
		}
		return "PARAMETRO_INVALIDO"
	})

	wrapper := ServerInterfaceWrapper{
		Handler: NewStrictHandlerWithOptions(s, nil, StrictHTTPServerOptions{
			ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
				writeResponseError(w, r, err)
			},
		}),
		HandlerMiddlewares: []MiddlewareFunc{swaggerMiddleware},
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			api.WriteError(w, r, api.NewError("INVALID_REQUEST", http.StatusBadRequest, err.Error()))
		},
	}

	var handler http.Handler

	handler = http.HandlerFunc(wrapper.PostEnrollments)
	handler = idempotencyMiddleware(handler)
	handler = jwtMiddleware(handler)
	handler = middleware.CertCN(handler)
	handler = clientCredentialsAuthMiddleware(handler)
	enrollmentMux.Handle("POST /enrollments", handler)

	handler = http.HandlerFunc(wrapper.GetEnrollment)
	handler = jwtMiddleware(handler)
	handler = clientCredentialsAuthMiddleware(handler)
	enrollmentMux.Handle("GET /enrollments/{enrollmentId}", handler)

	handler = http.HandlerFunc(wrapper.RiskSignals)
	handler = idempotencyMiddleware(handler)
	handler = jwtMiddleware(handler)
	handler = clientCredentialsAuthMiddleware(handler)
	enrollmentMux.Handle("POST /enrollments/{enrollmentId}/risk-signals", handler)

	handler = http.HandlerFunc(wrapper.EnrollmentCreateFidoRegistrationOptions)
	handler = idempotencyMiddleware(handler)
	handler = jwtMiddleware(handler)
	handler = authCodeAuthMiddleware(handler)
	enrollmentMux.Handle("POST /enrollments/{enrollmentId}/fido-registration-options", handler)

	handler = http.HandlerFunc(wrapper.EnrollmentRegisterFidoCredential)
	handler = idempotencyMiddleware(handler)
	handler = jwtMiddleware(handler)
	handler = authCodeAuthMiddleware(handler)
	enrollmentMux.Handle("POST /enrollments/{enrollmentId}/fido-registration", handler)

	handler = http.HandlerFunc(wrapper.EnrollmentCreateFidoSigningOptions)
	handler = idempotencyMiddleware(handler)
	handler = jwtMiddleware(handler)
	handler = clientCredentialsAuthMiddleware(handler)
	enrollmentMux.Handle("POST /enrollments/{enrollmentId}/fido-sign-options", handler)

	handler = http.HandlerFunc(wrapper.AuthorizeConsent)
	handler = idempotencyMiddleware(handler)
	handler = jwtMiddleware(handler)
	handler = authCodeAuthMiddleware(handler)
	enrollmentMux.Handle("POST /consents/{consentId}/authorise", handler)

	handler = http.HandlerFunc(wrapper.DeleteEnrollment)
	handler = idempotencyMiddleware(handler)
	handler = jwtMiddleware(handler)
	handler = clientCredentialsAuthMiddleware(handler)
	enrollmentMux.Handle("PATCH /enrollments/{enrollmentId}", handler)

	handler = middleware.FAPIID(nil)(enrollmentMux)
	mux.Handle("/open-banking/enrollments/v2/", http.StripPrefix("/open-banking/enrollments/v2", handler))
}

func (s Server) PostEnrollments(ctx context.Context, req PostEnrollmentsRequestObject) (PostEnrollmentsResponseObject, error) {
	clientID := ctx.Value(api.CtxKeyClientID).(string)
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	certCN := ctx.Value(api.CtxKeyCertCN).(string)

	e := &enrollment.Enrollment{
		UserIdentification: req.Body.Data.LoggedUser.Document.Identification,
		UserRel:            consent.Relation(req.Body.Data.LoggedUser.Document.Rel),
		Name:               req.Body.Data.EnrollmentName,
		Permissions:        req.Body.Data.Permissions,
		RelyingParty:       certCN,
		ClientID:           clientID,
		OrgID:              orgID,
	}

	if req.Body.Data.BusinessEntity != nil {
		rel := consent.Relation(req.Body.Data.BusinessEntity.Document.Rel)
		e.BusinessIdentification = &req.Body.Data.BusinessEntity.Document.Identification
		e.BusinessRel = &rel
	}

	var debtorAccount *payment.Account
	if req.Body.Data.DebtorAccount != nil {
		debtorAccount = &payment.Account{
			ISPB:   req.Body.Data.DebtorAccount.Ispb,
			Issuer: req.Body.Data.DebtorAccount.Issuer,
			Number: req.Body.Data.DebtorAccount.Number,
			Type:   payment.AccountType(req.Body.Data.DebtorAccount.AccountType),
		}
	}

	if err := s.service.Create(ctx, e, debtorAccount); err != nil {
		return nil, err
	}

	resp := ResponseCreateEnrollment{
		Data: struct {
			BusinessEntity       *BusinessEntity            "json:\"businessEntity,omitempty\""
			CreationDateTime     timeutil.DateTime          "json:\"creationDateTime\""
			DebtorAccount        *DebtorAccount             "json:\"debtorAccount,omitempty\""
			EnrollmentID         EnrollmentID               "json:\"enrollmentId\""
			EnrollmentName       *string                    "json:\"enrollmentName,omitempty\""
			ExpirationDateTime   *timeutil.DateTime         "json:\"expirationDateTime,omitempty\""
			LoggedUser           LoggedUser                 "json:\"loggedUser\""
			Permissions          []EnumEnrollmentPermission "json:\"permissions\""
			Status               EnumEnrollmentStatus       "json:\"status\""
			StatusUpdateDateTime timeutil.DateTime          "json:\"statusUpdateDateTime\""
		}{
			CreationDateTime:   e.CreatedAt,
			EnrollmentID:       EnrollmentID(e.URN()),
			EnrollmentName:     e.Name,
			ExpirationDateTime: e.ExpiresAt,
			LoggedUser: LoggedUser{
				Document: struct {
					Identification string "json:\"identification\""
					Rel            string "json:\"rel\""
				}{
					Identification: e.UserIdentification,
					Rel:            string(e.UserRel),
				},
			},
			Status:               EnumEnrollmentStatus(e.Status),
			StatusUpdateDateTime: e.StatusUpdatedAt,
		},
		Links: *api.NewLinks(s.baseURL + "/enrollments/" + e.URN()),
		Meta:  *api.NewMeta(),
	}

	for _, p := range e.Permissions {
		resp.Data.Permissions = append(resp.Data.Permissions, EnumEnrollmentPermission(p))
	}

	if e.BusinessIdentification != nil {
		rel := *e.BusinessRel
		resp.Data.BusinessEntity = &BusinessEntity{
			Document: struct {
				Identification string "json:\"identification\""
				Rel            string "json:\"rel\""
			}{
				Identification: *e.BusinessIdentification,
				Rel:            string(rel),
			},
		}
	}

	if e.DebtorAccount != nil {
		branch := account.DefaultBranch
		resp.Data.DebtorAccount = &DebtorAccount{
			Ispb:        bank.ISPB,
			Issuer:      &branch,
			Number:      e.DebtorAccount.Number,
			AccountType: EnumAccountPaymentsType(payment.ConvertAccountType(e.DebtorAccount.Type)),
		}
	}

	return PostEnrollments201JSONResponse{N201EnrollmentsCreatedJSONResponse(resp)}, nil
}

func (s Server) GetEnrollment(ctx context.Context, req GetEnrollmentRequestObject) (GetEnrollmentResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	e, err := s.service.Enrollment(ctx, enrollment.Query{ID: string(req.EnrollmentID), LoadDebtorAccount: true}, orgID)
	if err != nil {
		return nil, err
	}

	resp := ResponseEnrollment{
		Data: struct {
			BusinessEntity *BusinessEntity "json:\"businessEntity,omitempty\""
			Cancellation   *struct {
				AdditionalInformation *string "json:\"additionalInformation,omitempty\""
				CancelledBy           *struct {
					Document struct {
						Identification string "json:\"identification\""
						Rel            string "json:\"rel\""
					} "json:\"document\""
				} "json:\"cancelledBy,omitempty\""
				CancelledFrom EnumEnrollmentCancelledFrom                 "json:\"cancelledFrom\""
				Reason        ResponseEnrollment_Data_Cancellation_Reason "json:\"reason\""
				RejectedAt    *timeutil.DateTime                          "json:\"rejectedAt,omitempty\""
			} "json:\"cancellation,omitempty\""
			CreationDateTime timeutil.DateTime "json:\"creationDateTime\""
			DailyLimit       *string           "json:\"dailyLimit,omitempty\""
			DebtorAccount    *struct {
				AccountType EnumAccountPaymentsType "json:\"accountType\""
				Ispb        string                  "json:\"ispb\""
				Issuer      *string                 "json:\"issuer,omitempty\""
				Number      string                  "json:\"number\""
			} "json:\"debtorAccount,omitempty\""
			EnrollmentID         EnrollmentID               "json:\"enrollmentId\""
			EnrollmentName       *string                    "json:\"enrollmentName,omitempty\""
			ExpirationDateTime   *timeutil.DateTime         "json:\"expirationDateTime,omitempty\""
			LoggedUser           LoggedUser                 "json:\"loggedUser\""
			Permissions          []EnumEnrollmentPermission "json:\"permissions\""
			Status               EnumEnrollmentStatus       "json:\"status\""
			StatusUpdateDateTime timeutil.DateTime          "json:\"statusUpdateDateTime\""
			TransactionLimit     *string                    "json:\"transactionLimit,omitempty\""
		}{
			CreationDateTime:   e.CreatedAt,
			EnrollmentID:       EnrollmentID(e.URN()),
			EnrollmentName:     e.Name,
			ExpirationDateTime: e.ExpiresAt,
			LoggedUser: LoggedUser{
				Document: struct {
					Identification string "json:\"identification\""
					Rel            string "json:\"rel\""
				}{
					Identification: e.UserIdentification,
					Rel:            string(e.UserRel),
				},
			},
			Status:               EnumEnrollmentStatus(e.Status),
			StatusUpdateDateTime: e.StatusUpdatedAt,
			TransactionLimit:     e.TransactionLimit,
			DailyLimit:           e.DailyLimit,
		},
		Links: *api.NewLinks(s.baseURL + "/enrollments/" + e.URN()),
		Meta:  *api.NewMeta(),
	}

	for _, p := range e.Permissions {
		resp.Data.Permissions = append(resp.Data.Permissions, EnumEnrollmentPermission(p))
	}

	if e.BusinessIdentification != nil {
		rel := *e.BusinessRel
		resp.Data.BusinessEntity = &BusinessEntity{
			Document: struct {
				Identification string "json:\"identification\""
				Rel            string "json:\"rel\""
			}{
				Identification: *e.BusinessIdentification,
				Rel:            string(rel),
			},
		}
	}

	if e.DebtorAccount != nil {
		branch := account.DefaultBranch
		resp.Data.DebtorAccount = &struct {
			AccountType EnumAccountPaymentsType "json:\"accountType\""
			Ispb        string                  "json:\"ispb\""
			Issuer      *string                 "json:\"issuer,omitempty\""
			Number      string                  "json:\"number\""
		}{
			Ispb:        bank.ISPB,
			Issuer:      &branch,
			Number:      e.DebtorAccount.Number,
			AccountType: EnumAccountPaymentsType(payment.ConvertAccountType(e.DebtorAccount.Type)),
		}
	}

	if cancellation := e.Cancellation; cancellation != nil {
		resp.Data.Cancellation = &struct {
			AdditionalInformation *string "json:\"additionalInformation,omitempty\""
			CancelledBy           *struct {
				Document struct {
					Identification string "json:\"identification\""
					Rel            string "json:\"rel\""
				} "json:\"document\""
			} "json:\"cancelledBy,omitempty\""
			CancelledFrom EnumEnrollmentCancelledFrom                 "json:\"cancelledFrom\""
			Reason        ResponseEnrollment_Data_Cancellation_Reason "json:\"reason\""
			RejectedAt    *timeutil.DateTime                          "json:\"rejectedAt,omitempty\""
		}{
			AdditionalInformation: cancellation.AdditionalInfo,
			CancelledFrom:         EnumEnrollmentCancelledFrom(cancellation.From),
			RejectedAt:            cancellation.At,
		}

		if cancellation.By != nil {
			resp.Data.Cancellation.CancelledBy = &struct {
				Document struct {
					Identification string "json:\"identification\""
					Rel            string "json:\"rel\""
				} "json:\"document\""
			}{
				Document: struct {
					Identification string "json:\"identification\""
					Rel            string "json:\"rel\""
				}{
					Identification: *cancellation.By,
					Rel:            string(consent.RelationCPF),
				},
			}
		}

		reason := ResponseEnrollment_Data_Cancellation_Reason{}
		if cancellation.RejectionReason != nil {
			reason.FromResponseEnrollmentDataCancellationReason0(ResponseEnrollmentDataCancellationReason0{
				RejectionReason: EnrollmentRejectionReason(*cancellation.RejectionReason),
			})
		}
		if cancellation.RevocationReason != nil {
			reason.FromResponseEnrollmentDataCancellationReason1(ResponseEnrollmentDataCancellationReason1{
				RevocationReason: EnrollmentRevocationReason(*cancellation.RevocationReason),
			})
		}

		resp.Data.Cancellation.Reason = reason
	}

	return GetEnrollment200JSONResponse{N200EnrollmentsEnrollmentIDReadJSONResponse(resp)}, nil
}

func (s Server) RiskSignals(ctx context.Context, req RiskSignalsRequestObject) (RiskSignalsResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)

	if err := s.service.AddRiskSignals(ctx, req.EnrollmentID, orgID, req.Body.Data); err != nil {
		return nil, err
	}

	return RiskSignals204Response{}, nil
}

func (s Server) EnrollmentCreateFidoRegistrationOptions(ctx context.Context, req EnrollmentCreateFidoRegistrationOptionsRequestObject) (EnrollmentCreateFidoRegistrationOptionsResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)

	e, err := s.service.InitRegistration(ctx, req.EnrollmentID, orgID, enrollment.FIDOOptions{
		RelyingParty: req.Body.Data.Rp,
	})
	if err != nil {
		return nil, err
	}

	timeout := int(enrollment.CredentialRegistrationTimeout.Seconds())
	resp := EnrollmentFidoRegistrationOptions{
		Data: struct {
			Attestation            *string                                  "json:\"attestation,omitempty\""
			AttestationFormats     *[]string                                "json:\"attestationFormats,omitempty\""
			AuthenticatorSelection *FidoAuthenticatorSelectionCriteria      "json:\"authenticatorSelection,omitempty\""
			Challenge              string                                   "json:\"challenge\""
			EnrollmentID           EnrollmentID                             "json:\"enrollmentId\""
			ExcludeCredentials     *[]FidoPublicKeyCredentialDescriptor     "json:\"excludeCredentials,omitempty\""
			Extensions             *map[string]any                          "json:\"extensions,omitempty\""
			PubKeyCredParams       []FidoPublicKeyCredentialCreationOptions "json:\"pubKeyCredParams\""
			Rp                     FidoRelyingParty                         "json:\"rp\""
			Timeout                *int                                     "json:\"timeout,omitempty\""
			User                   FidoUser                                 "json:\"user\""
		}{
			EnrollmentID: EnrollmentID(e.URN()),
			Rp: FidoRelyingParty{
				ID:   e.RelyingParty,
				Name: e.Client.Name,
			},
			Timeout: &timeout,
			User: FidoUser{
				DisplayName: e.Owner.Name,
				ID:          e.Owner.ID.String(),
				Name:        e.Owner.Username,
			},
		},
		Meta: *api.NewMeta(),
	}

	if e.Challenge != nil {
		resp.Data.Challenge = *e.Challenge
	}

	for _, p := range enrollment.PublicKeyCredentialParameters {
		resp.Data.PubKeyCredParams = append(resp.Data.PubKeyCredParams, FidoPublicKeyCredentialCreationOptions{
			Type: string(p.Type),
			Alg:  int(p.Algorithm),
		})
	}

	return EnrollmentCreateFidoRegistrationOptions201JSONResponse{N201EnrollmentFidoRegistrationOptionsJSONResponse(resp)}, nil
}

func (s Server) AuthorizeConsent(ctx context.Context, req AuthorizeConsentRequestObject) (AuthorizeConsentResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	assertion := enrollment.FIDOAssertion{
		ID:    req.Body.Data.FidoAssertion.ID,
		RawID: req.Body.Data.FidoAssertion.RawID,
		Type:  req.Body.Data.FidoAssertion.Type,
		Response: struct {
			ClientDataJSON    string "json:\"clientDataJSON,omitempty\""
			AuthenticatorData string "json:\"authenticatorData,omitempty\""
			Signature         string "json:\"signature,omitempty\""
			UserHandle        string "json:\"userHandle,omitempty\""
		}{
			ClientDataJSON:    req.Body.Data.FidoAssertion.Response.ClientDataJSON,
			AuthenticatorData: req.Body.Data.FidoAssertion.Response.AuthenticatorData,
			Signature:         req.Body.Data.FidoAssertion.Response.Signature,
			UserHandle:        req.Body.Data.FidoAssertion.Response.UserHandle,
		},
	}
	if err := s.service.AuthorizeConsent(
		ctx,
		req.ParameterConsentID,
		req.Body.Data.EnrollmentID,
		orgID,
		assertion,
	); err != nil {
		return nil, err
	}

	return AuthorizeConsent204Response{}, nil
}

func (s Server) DeleteEnrollment(ctx context.Context, req DeleteEnrollmentRequestObject) (DeleteEnrollmentResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	cancellation := enrollment.Cancellation{
		From:           payment.CancelledFromInitiator,
		AdditionalInfo: req.Body.Data.Cancellation.AdditionalInformation,
	}
	if by := req.Body.Data.Cancellation.CancelledBy; by != nil {
		cancellation.By = &by.Document.Identification
	}
	if rejection, err := req.Body.Data.Cancellation.Reason.AsDeleteEnrollmentJSONBodyDataCancellationReason0(); err == nil && rejection.RejectionReason != "" {
		reason := enrollment.RejectionReason(rejection.RejectionReason)
		cancellation.RejectionReason = &reason
	}
	if revocation, err := req.Body.Data.Cancellation.Reason.AsDeleteEnrollmentJSONBodyDataCancellationReason1(); err == nil && revocation.RevocationReason != "" {
		reason := enrollment.RevocationReason(revocation.RevocationReason)
		cancellation.RevocationReason = &reason
	}

	if err := s.service.CancelByID(ctx, req.EnrollmentID, orgID, cancellation); err != nil {
		return nil, err
	}

	return DeleteEnrollment204Response{}, nil
}

func (s Server) EnrollmentRegisterFidoCredential(ctx context.Context, request EnrollmentRegisterFidoCredentialRequestObject) (EnrollmentRegisterFidoCredentialResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	credentialType := "public-key"
	if request.Body.Data.Type != nil {
		credentialType = *request.Body.Data.Type
	}
	if err := s.service.RegisterCredential(ctx, request.EnrollmentID, orgID, enrollment.Credential{
		ID:    request.Body.Data.ID,
		RawID: request.Body.Data.RawID,
		Type:  credentialType,
		Response: struct {
			ClientDataJSON    string "json:\"clientDataJSON,omitempty\""
			AttestationObject string "json:\"attestationObject,omitempty\""
		}{
			ClientDataJSON:    request.Body.Data.Response.ClientDataJSON,
			AttestationObject: request.Body.Data.Response.AttestationObject,
		},
	}); err != nil {
		return nil, err
	}

	return EnrollmentRegisterFidoCredential204Response{}, nil
}

func (s Server) EnrollmentCreateFidoSigningOptions(ctx context.Context, req EnrollmentCreateFidoSigningOptionsRequestObject) (EnrollmentCreateFidoSigningOptionsResponseObject, error) {
	orgID := ctx.Value(api.CtxKeyOrgID).(string)

	challenge, err := s.service.InitAuthorization(ctx, req.Body.Data.ConsentIDType, req.EnrollmentID, orgID, enrollment.FIDOOptions{
		RelyingParty: req.Body.Data.Rp,
	})
	if err != nil {
		return nil, err
	}

	resp := EnrollmentFidoSignOptions{
		Data: struct {
			AllowCredentials *[]FidoPublicKeyCredentialDescriptor "json:\"allowCredentials,omitempty\""
			Challenge        string                               "json:\"challenge\""
			Extensions       *map[string]any                      "json:\"extensions,omitempty\""
			RpID             *string                              "json:\"rpId,omitempty\""
			Timeout          *int32                               "json:\"timeout,omitempty\""
			UserVerification *string                              "json:\"userVerification,omitempty\""
		}{
			RpID:      &req.Body.Data.Rp,
			Challenge: challenge,
		},
		Meta: *api.NewMeta(),
	}

	return EnrollmentCreateFidoSigningOptions201JSONResponse{N201EnrollmentFidoSignOptionsJSONResponse(resp)}, nil
}

func writeResponseError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, enrollment.ErrMissingValue) {
		api.WriteError(w, r, api.NewError("PARAMETRO_NAO_INFORMADO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, enrollment.ErrInvalidData) {
		api.WriteError(w, r, api.NewError("PARAMETRO_INVALIDO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, enrollment.ErrInvalidPermissions) {
		api.WriteError(w, r, api.NewError("PERMISSOES_INVALIDAS", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, enrollment.ErrInvalidPublicKey) {
		api.WriteError(w, r, api.NewError("PUBLIC_KEY_INVALIDA", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, enrollment.ErrInvalidStatus) {
		api.WriteError(w, r, api.NewError("STATUS_VINCULO_INVALIDO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, enrollment.ErrInvalidOrigin) {
		api.WriteError(w, r, api.NewError("ORIGEM_FIDO_INVALIDA", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, enrollment.ErrInvalidRelyingParty) {
		api.WriteError(w, r, api.NewError("RP_INVALIDA", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, enrollment.ErrInvalidAssertion) {
		api.WriteError(w, r, api.NewError("RISCO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, payment.ErrInvalidConsentStatus) {
		api.WriteError(w, r, api.NewError("STATUS_CONSENTIMENTO_INVALIDO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.Is(err, autopayment.ErrInvalidConsentStatus) {
		api.WriteError(w, r, api.NewError("STATUS_CONSENTIMENTO_INVALIDO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	if errors.As(err, &errorutil.Error{}) {
		api.WriteError(w, r, api.NewError("PARAMETRO_INVALIDO", http.StatusUnprocessableEntity, err.Error()))
		return
	}

	api.WriteError(w, r, err)
}

func (t DeleteEnrollmentJSONBody_Data_Cancellation_Reason) AsDeleteEnrollmentJSONBodyDataCancellationReason0() (DeleteEnrollmentJSONBodyDataCancellationReason0, error) {
	var body DeleteEnrollmentJSONBodyDataCancellationReason0
	err := json.Unmarshal(t.union, &body)
	return body, err
}

func (t DeleteEnrollmentJSONBody_Data_Cancellation_Reason) AsDeleteEnrollmentJSONBodyDataCancellationReason1() (DeleteEnrollmentJSONBodyDataCancellationReason1, error) {
	var body DeleteEnrollmentJSONBodyDataCancellationReason1
	err := json.Unmarshal(t.union, &body)
	return body, err
}

func (t DeleteEnrollmentJSONBody_Data_Cancellation_Reason) MarshalJSON() ([]byte, error) {
	b, err := t.union.MarshalJSON()
	return b, err
}

func (t *DeleteEnrollmentJSONBody_Data_Cancellation_Reason) UnmarshalJSON(b []byte) error {
	err := t.union.UnmarshalJSON(b)
	return err
}
