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
			BirthDate:                   id.BirthDate,
			BrandName:                   s.config.Brand(),
			CivilName:                   id.CivilName,
			CompaniesCnpj:               id.CompanyCNPJs,
			HasBrazilianNationality:     id.IsBrazilian,
			MaritalStatusAdditionalInfo: id.MaritalStatusAdditionalInfo,
			PersonalID:                  id.ID.String(),
			SocialName:                  id.SocialName,
			UpdateDateTime:              id.UpdatedAt,
		}

		if id.Passport != nil {
			data.Documents.Passport = &PersonalPassport{
				Number:         id.Passport.Number,
				Country:        id.Passport.Country,
				ExpirationDate: id.Passport.ExpiresAt,
				IssueDate:      id.Passport.IssuedAt,
			}
		}

		if id.Filiations != nil {
			filiationData := make([]struct {
				CivilName  string            `json:"civilName"`
				SocialName *string           `json:"socialName,omitempty"`
				Type       EnumFiliationType `json:"type"`
			}, len(*id.Filiations))

			for i, fil := range *id.Filiations {
				filiationType := EnumFiliationType(fil.Type)
				filiationData[i] = struct {
					CivilName  string            `json:"civilName"`
					SocialName *string           `json:"socialName,omitempty"`
					Type       EnumFiliationType `json:"type"`
				}{
					CivilName:  fil.CivilName,
					SocialName: fil.SocialName,
					Type:       filiationType,
				}
			}
			data.Filiation = &filiationData
		}

		if len(id.Nationalities) > 0 {
			nationalityData := make([]Nationality, len(id.Nationalities))
			for i, nat := range id.Nationalities {
				documents := make([]NationalityOtherDocument, len(nat.Documents))
				for j, doc := range nat.Documents {
					documents[j] = NationalityOtherDocument{
						AdditionalInfo: doc.AdditionalInfo,
						Country:        doc.Country,
						ExpirationDate: doc.ExpiresAt,
						IssueDate:      doc.IssuedAt,
						Number:         doc.Number,
						Type:           doc.Type,
					}
				}
				nationalityData[i] = Nationality{
					Documents:              documents,
					OtherNationalitiesInfo: nat.CountryCode,
				}
			}
			data.Nationality = &nationalityData
		}

		if id.OtherDocuments != nil {
			otherDocsData := make([]PersonalOtherDocument, len(*id.OtherDocuments))
			for i, doc := range *id.OtherDocuments {
				docType := EnumPersonalOtherDocumentType(doc.Type)
				otherDocsData[i] = PersonalOtherDocument{
					AdditionalInfo:     doc.AdditionalInfo,
					CheckDigit:         doc.CheckDigit,
					ExpirationDate:     doc.ExpiresAt,
					Number:             doc.Number,
					Type:               docType,
					TypeAdditionalInfo: doc.TypeAdditionalInfo,
				}
			}
			data.OtherDocuments = &otherDocsData
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

		for _, phone := range id.Contact.Phones {
			data.Contacts.Phones = append(data.Contacts.Phones, CustomerPhone{
				AdditionalInfo:     phone.AdditionalInfo,
				AreaCode:           phone.AreaCode,
				CountryCallingCode: phone.CountryCode,
				IsMain:             phone.IsMain,
				Number:             phone.Number,
				PhoneExtension:     phone.Extension,
				Type:               EnumCustomerPhoneType(phone.Type),
			})
		}

		for _, address := range id.Contact.Addresses {
			postalAddress := PersonalPostalAddress{
				AdditionalInfo: address.AdditionalInfo,
				Address:        address.Address,
				Country:        address.Country,
				CountryCode:    address.CountryCode,
				DistrictName:   address.District,
				GeographicCoordinates: &GeographicCoordinates{
					Latitude:  address.GeographicCoordinates.Latitude,
					Longitude: address.GeographicCoordinates.Longitude,
				},
				IbgeTownCode: address.IBGECode,
				IsMain:       address.IsMain,
				PostCode:     address.PostCode,
				TownName:     address.Town,
			}

			if address.CountrySubdivision != nil {
				countrySubdivision := EnumCountrySubDivision(*address.CountrySubdivision)
				postalAddress.CountrySubDivision = &countrySubdivision
			}

			data.Contacts.PostalAddresses = append(data.Contacts.PostalAddresses, postalAddress)
		}

		resp.Data = append(resp.Data, data)
	}

	return CustomersGetPersonalIdentifications200JSONResponse{OKResponsePersonalCustomersIdentificationJSONResponse(resp)}, nil
}

func (s Server) CustomersGetPersonalQualifications(ctx context.Context, req CustomersGetPersonalQualificationsRequestObject) (CustomersGetPersonalQualificationsResponseObject, error) {
	return nil, nil
}
