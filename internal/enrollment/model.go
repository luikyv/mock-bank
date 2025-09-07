package enrollment

import (
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/mock-bank/internal/account"
	"github.com/luikyv/mock-bank/internal/client"
	"github.com/luikyv/mock-bank/internal/consent"
	"github.com/luikyv/mock-bank/internal/payment"
	"github.com/luikyv/mock-bank/internal/timeutil"
	"github.com/luikyv/mock-bank/internal/user"
)

const (
	CredentialRegistrationTimeout = 300000 * time.Second
	URNPrefix                     = "urn:mockbank:enrollment:"
	defaultDailyLimit             = "500.00"
	defaultTransactionLimit       = "100.00"
)

var (
	ScopeID = goidc.NewDynamicScope("enrollment", func(s string) bool {
		return strings.HasPrefix(s, "enrollment:")
	})
	ScopeConsent = goidc.NewScope("nrp-consents")
)

var PublicKeyCredentialParameters = []protocol.CredentialParameter{
	{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgRS256},
	{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgPS256},
	{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256},
}

type Enrollment struct {
	ID                     uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	Status                 Status
	StatusUpdatedAt        timeutil.DateTime
	Permissions            []Permission `gorm:"serializer:json"`
	ExpiresAt              *timeutil.DateTime
	UserIdentification     string
	UserRel                consent.Relation
	BusinessIdentification *string
	BusinessRel            *consent.Relation
	OwnerID                uuid.UUID
	Owner                  *user.User
	DebtorAccountID        *uuid.UUID `gorm:"column:account_id"`
	DebtorAccount          *account.Account
	Name                   *string
	TransactionLimit       *string
	DailyLimit             *string
	RiskSignals            *map[string]any `gorm:"serializer:json"`
	Cancellation           *Cancellation   `gorm:"serializer:json"`
	ClientID               string
	Client                 *client.Client
	RelyingParty           string
	Challenge              *string
	PublicKey              *string
	Version                string

	OrgID     string
	CreatedAt timeutil.DateTime
	UpdatedAt timeutil.DateTime
}

func (Enrollment) TableName() string {
	return "enrollments"
}

func (e Enrollment) URN() string {
	return URN(e.ID)
}

type Status string

const (
	StatusAwaitingRiskSignals             Status = "AWAITING_RISK_SIGNALS"
	StatusAwaitingAccountHolderValidation Status = "AWAITING_ACCOUNT_HOLDER_VALIDATION"
	StatusAwaitingEnrollment              Status = "AWAITING_ENROLLMENT"
	StatusAuthorized                      Status = "AUTHORISED"
	StatusRevoked                         Status = "REVOKED"
	StatusRejected                        Status = "REJECTED"
)

type Permission string

const (
	PermissionPaymentsInitiate          Permission = "PAYMENTS_INITIATE"
	PermissionRecurringPaymentsInitiate Permission = "RECURRING_PAYMENTS_INITIATE"
)

type Cancellation struct {
	RejectionReason  *RejectionReason       `json:"rejection_reason,omitempty"`
	RevocationReason *RevocationReason      `json:"revocation_reason,omitempty"`
	From             payment.TerminatedFrom `json:"cancellation_from"`
	At               *timeutil.DateTime     `json:"cancelled_at,omitempty"`
	By               *string                `json:"cancelled_by,omitempty"`
	AdditionalInfo   *string                `json:"additional_info,omitempty"`
}

type RejectionReason string

const (
	RejectionReasonAwaitingRiskSignals             RejectionReason = "REJEITADO_TEMPO_EXPIRADO_RISK_SIGNALS"
	RejectionReasonAwaitingAccountHolderValidation RejectionReason = "REJEITADO_TEMPO_EXPIRADO_ACCOUNT_HOLDER_VALIDATION"
	RejectionReasonAwaitingEnrollment              RejectionReason = "REJEITADO_TEMPO_EXPIRADO_ENROLLMENT"
	RejectionReasonMaxChallengesReached            RejectionReason = "REJEITADO_MAXIMO_CHALLENGES_ATINGIDO"
	RejectionReasonManualRejection                 RejectionReason = "REJEITADO_MANUALMENTE"
	RejectionReasonDeviceIncompatible              RejectionReason = "REJEITADO_DISPOSITIVO_INCOMPATIVEL"
	RejectionReasonInfrastructureFailure           RejectionReason = "REJEITADO_FALHA_INFRAESTRUTURA"
	RejectionReasonHybridFlowFailure               RejectionReason = "REJEITADO_FALHA_HYBRID_FLOW"
	RejectionReasonFidoFailure                     RejectionReason = "REJEITADO_FALHA_FIDO"
	RejectionReasonInternalSecurityFailure         RejectionReason = "REJEITADO_SEGURANCA_INTERNA"
	RejectionReasonOther                           RejectionReason = "REJEITADO_OUTRO"
)

type RevocationReason string

const (
	RevocationReasonManualRevocation        RevocationReason = "REVOGADO_MANUALMENTE"
	RevocationReasonExpiredRevocation       RevocationReason = "REVOGADO_VALIDADE_EXPIRADA"
	RevocationReasonInfrastructureFailure   RevocationReason = "REVOGADO_FALHA_INFRAESTRUTURA"
	RevocationReasonInternalSecurityFailure RevocationReason = "REVOGADO_SEGURANCA_INTERNA"
	RevocationReasonOther                   RevocationReason = "REVOGADO_OUTRO"
)

type Query struct {
	ID                string
	LoadDebtorAccount bool
	LoadOwner         bool
	LoadClient        bool
}

type FIDOOptions struct {
	RelyingParty string
}

type Platform string

const (
	PlatformAndroid       Platform = "ANDROID"
	PlatformIOS           Platform = "IOS"
	PlatformBrowser       Platform = "BROWSER"
	PlatformCrossPlatform Platform = "CROSS_PLATFORM"
)

type Credential struct {
	ID       string `json:"id"`
	RawID    string `json:"rawId"`
	Type     string `json:"type"`
	Response struct {
		ClientDataJSON    string `json:"clientDataJSON,omitempty"`
		AttestationObject string `json:"attestationObject,omitempty"`
	} `json:"response,omitempty"`
}

type FIDOAssertion struct {
	ID       string `json:"id"`
	RawID    string `json:"rawId"`
	Type     string `json:"type"`
	Response struct {
		ClientDataJSON    string `json:"clientDataJSON,omitempty"`
		AuthenticatorData string `json:"authenticatorData,omitempty"`
		Signature         string `json:"signature,omitempty"`
		UserHandle        string `json:"userHandle,omitempty"`
	} `json:"response,omitempty"`
}
