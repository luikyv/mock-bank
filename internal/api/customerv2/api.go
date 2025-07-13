//go:generate oapi-codegen -config=./config.yml -package=customerv2 -o=./api_gen.go ./swagger.yml
package customerv2

import (
	"context"

	"github.com/luikyv/go-oidc/pkg/provider"
	"github.com/luikyv/mock-bank/internal/api"
	"github.com/luikyv/mock-bank/internal/customer"
	"github.com/luikyv/mock-bank/internal/page"
	openapi_types "github.com/oapi-codegen/runtime/types"
)

var _ StrictServerInterface = Server{}

type BankConfig interface {
	Host() string
	Brand() string
}

type Server struct {
	config  BankConfig
	baseURL string
	service customer.Service
	op      *provider.Provider
}

func NewServer(config BankConfig, service customer.Service, op *provider.Provider) Server {
	return Server{
		config:  config,
		baseURL: config.Host() + "/open-banking/customers/v2",
		service: service,
		op:      op,
	}
}

func (s Server) CustomersGetBusinessFinancialRelations(ctx context.Context, req CustomersGetBusinessFinancialRelationsRequestObject) (CustomersGetBusinessFinancialRelationsResponseObject, error) {
	return nil, nil
}

func (s Server) CustomersGetBusinessIdentifications(ctx context.Context, req CustomersGetBusinessIdentificationsRequestObject) (CustomersGetBusinessIdentificationsResponseObject, error) {
	return nil, nil
}

func (s Server) CustomersGetBusinessQualifications(ctx context.Context, req CustomersGetBusinessQualificationsRequestObject) (CustomersGetBusinessQualificationsResponseObject, error) {
	return nil, nil
}

func (s Server) CustomersGetPersonalFinancialRelations(ctx context.Context, req CustomersGetPersonalFinancialRelationsRequestObject) (CustomersGetPersonalFinancialRelationsResponseObject, error) {
	return nil, nil
}

// TODO: Finish this.
func (s Server) CustomersGetPersonalIdentifications(ctx context.Context, req CustomersGetPersonalIdentificationsRequestObject) (CustomersGetPersonalIdentificationsResponseObject, error) {
	ownerID := ctx.Value(api.CtxKeySubject).(string)
	orgID := ctx.Value(api.CtxKeyOrgID).(string)
	pag := page.NewPagination(req.Params.Page, req.Params.PageSize)
	ids, err := s.service.PersonalIdentifications(ctx, ownerID, orgID, pag)
	if err != nil {
		return nil, err
	}

	resp := ResponsePersonalCustomersIdentification{
		Data:  []PersonalIdentificationData{},
		Links: *api.NewPaginatedLinks(s.baseURL+"/personal/identifications", ids),
		Meta:  *api.NewPaginatedMeta(ids),
	}

	for _, id := range ids.Records {
		data := PersonalIdentificationData{
			BirthDate:     id.BirthDate,
			BrandName:     s.config.Brand(),
			CivilName:     id.CivilName,
			CompaniesCnpj: id.CompanyCNPJs,
			// Contacts:                    "",
			// Documents:                   "",
			// Filiation:                   "",
			HasBrazilianNationality:     id.IsBrazilian,
			MaritalStatusAdditionalInfo: id.MaritalStatusAdditionalInfo,
			// Nationality:                 "",
			// OtherDocuments:              "",
			PersonalID:     id.ID.String(),
			SocialName:     id.SocialName,
			UpdateDateTime: id.UpdatedAt,
		}

		if id.MaritalStatus != nil {
			maritalStatus := EnumMaritalStatusCode(*id.MaritalStatus)
			data.MaritalStatusCode = &maritalStatus
		}

		if id.Sex != nil {
			sex := EnumSex(*id.Sex)
			data.Sex = &sex
		}

		for _, email := range id.Contact.Emails {
			data.Contacts.Emails = append(data.Contacts.Emails, CustomerEmail{
				Email:  openapi_types.Email(email.Email),
				IsMain: email.IsMain,
			})
		}

		for range id.Contact.Phones {
			data.Contacts.Phones = append(data.Contacts.Phones, CustomerPhone{})
		}

		resp.Data = append(resp.Data, data)
	}

	return CustomersGetPersonalIdentifications200JSONResponse{OKResponsePersonalCustomersIdentificationJSONResponse(resp)}, nil
}

func (s Server) CustomersGetPersonalQualifications(ctx context.Context, req CustomersGetPersonalQualificationsRequestObject) (CustomersGetPersonalQualificationsResponseObject, error) {
	return nil, nil
}
