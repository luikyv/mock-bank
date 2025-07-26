package customer

import (
	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/mock-bank/internal/timeutil"
)

var Scope = goidc.NewScope("customers")

type PersonalIdentification struct {
	ID                          uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	CivilName                   string
	SocialName                  *string
	BirthDate                   timeutil.BrazilDate
	MaritalStatus               *MaritalStatus
	MaritalStatusAdditionalInfo *string
	Sex                         *Sex
	CompanyCNPJs                []string `gorm:"column:company_cnpjs;serializer:json"`
	Passport                    *Passport
	OtherDocuments              *[]OtherDocument `gorm:"serializer:json"`
	IsBrazilian                 bool
	Nationalities               []Nationality `gorm:"serializer:json"`
	Filiations                  *[]Filiation  `gorm:"serializer:json"`
	Contact                     Contact       `gorm:"serializer:json"`

	OrgID     string
	CrossOrg  bool
	CreatedAt timeutil.DateTime
	UpdatedAt timeutil.DateTime
}

type MaritalStatus string

const (
	MaritalStatusSingle    MaritalStatus = "SOLTEIRO"
	MaritalStatusMarried   MaritalStatus = "CASADO"
	MaritalStatusDivorced  MaritalStatus = "DIVORCIADO"
	MaritalStatusWidowed   MaritalStatus = "VIUVO"
	MaritalStatusSeparated MaritalStatus = "SEPARADO_JUDICIALMENTE"
	MaritalStatusUnion     MaritalStatus = "UNIAO_ESTAVEL"
	MaritalStatusOther     MaritalStatus = "OUTRO"
)

type Sex string

const (
	SexFemale Sex = "FEMININO"
	SexMale   Sex = "MASCULINO"
	SexOther  Sex = "OUTRO"
)

type Passport struct {
	Number    string               `json:"number"`
	Country   string               `json:"country"`
	ExpiresAt *timeutil.BrazilDate `json:"expires_at"`
	IssuedAt  *timeutil.BrazilDate `json:"issued_at"`
}

type OtherDocument struct {
	Type               OtherDocumentType    `json:"type"`
	TypeAdditionalInfo *string              `json:"type_additional_info,omitempty"`
	Number             string               `json:"number"`
	CheckDigit         *string              `json:"check_digit,omitempty"`
	AdditionalInfo     *string              `json:"additional_info,omitempty"`
	ExpiresAt          *timeutil.BrazilDate `json:"expires_at,omitempty"`
}

type OtherDocumentType string

const (
	OtherDocumentTypeCNH   OtherDocumentType = "CNH"
	OtherDocumentTypeRG    OtherDocumentType = "RG"
	OtherDocumentTypeNIF   OtherDocumentType = "NIF"
	OtherDocumentTypeRNE   OtherDocumentType = "RNE"
	OtherDocumentTypeOther OtherDocumentType = "OUTROS"
)

type Nationality struct {
	CountryCode string            `json:"country_code"`
	Documents   []ForeignDocument `json:"documents"`
}

type ForeignDocument struct {
	Type           string               `json:"type"`
	Number         string               `json:"number"`
	IssuedAt       *timeutil.BrazilDate `json:"issued_at,omitempty"`
	ExpiresAt      *timeutil.BrazilDate `json:"expires_at,omitempty"`
	Country        *string              `json:"country,omitempty"`
	AdditionalInfo *string              `json:"additional_info,omitempty"`
}

type Filiation struct {
	Type       FiliationType `json:"type"`
	CivilName  string        `json:"civil_name"`
	SocialName *string       `json:"social_name,omitempty"`
}

type FiliationType string

const (
	FiliationTypeMother FiliationType = "MAE"
	FiliationTypeFather FiliationType = "PAI"
)

type Contact struct {
	Phones    []Phone   `json:"phones"`
	Emails    []Email   `json:"emails"`
	Addresses []Address `json:"addresses"`
}

type Address struct {
	IsMain                bool                   `json:"is_main"`
	Address               string                 `json:"address"`
	AdditionalInfo        *string                `json:"additional_info,omitempty"`
	District              *string                `json:"district,omitempty"`
	Town                  string                 `json:"town"`
	IBGECode              *string                `json:"ibge_code,omitempty"`
	CountrySubdivision    *CountrySubdivision    `json:"country_subdivision,omitempty"`
	PostCode              string                 `json:"post_code"`
	Country               string                 `json:"country"`
	CountryCode           *string                `json:"country_code,omitempty"`
	GeographicCoordinates *GeographicCoordinates `json:"geographic_coordinates,omitempty"`
}

type CountrySubdivision string

const (
	CountrySubdivisionAC CountrySubdivision = "AC" // Acre
	CountrySubdivisionAL CountrySubdivision = "AL" // Alagoas
	CountrySubdivisionAP CountrySubdivision = "AP" // Amapá
	CountrySubdivisionAM CountrySubdivision = "AM" // Amazonas
	CountrySubdivisionBA CountrySubdivision = "BA" // Bahia
	CountrySubdivisionCE CountrySubdivision = "CE" // Ceará
	CountrySubdivisionDF CountrySubdivision = "DF" // Distrito Federal
	CountrySubdivisionES CountrySubdivision = "ES" // Espírito Santo
	CountrySubdivisionGO CountrySubdivision = "GO" // Goiás
	CountrySubdivisionMA CountrySubdivision = "MA" // Maranhão
	CountrySubdivisionMT CountrySubdivision = "MT" // Mato Grosso
	CountrySubdivisionMS CountrySubdivision = "MS" // Mato Grosso do Sul
	CountrySubdivisionMG CountrySubdivision = "MG" // Minas Gerais
	CountrySubdivisionPA CountrySubdivision = "PA" // Pará
	CountrySubdivisionPB CountrySubdivision = "PB" // Paraíba
	CountrySubdivisionPR CountrySubdivision = "PR" // Paraná
	CountrySubdivisionPE CountrySubdivision = "PE" // Pernambuco
	CountrySubdivisionPI CountrySubdivision = "PI" // Piauí
	CountrySubdivisionRJ CountrySubdivision = "RJ" // Rio de Janeiro
	CountrySubdivisionRN CountrySubdivision = "RN" // Rio Grande do Norte
	CountrySubdivisionRS CountrySubdivision = "RS" // Rio Grande do Sul
	CountrySubdivisionRO CountrySubdivision = "RO" // Rondônia
	CountrySubdivisionRR CountrySubdivision = "RR" // Roraima
	CountrySubdivisionSC CountrySubdivision = "SC" // Santa Catarina
	CountrySubdivisionSP CountrySubdivision = "SP" // São Paulo
	CountrySubdivisionSE CountrySubdivision = "SE" // Sergipe
	CountrySubdivisionTO CountrySubdivision = "TO" // Tocantins
)

type GeographicCoordinates struct {
	Latitude  string `json:"latitude"`
	Longitude string `json:"longitude"`
}

type Phone struct {
	IsMain         bool      `json:"is_main"`
	Type           PhoneType `json:"type"`
	AdditionalInfo *string   `json:"additional_info,omitempty"`
	CountryCode    *string   `json:"country_code,omitempty"`
	AreaCode       string    `json:"area_code"`
	Number         string    `json:"number"`
	Extension      *string   `json:"extension,omitempty"`
}

type PhoneType string

const (
	PhoneTypeFixed  PhoneType = "FIXO"
	PhoneTypeMobile PhoneType = "MOVEL"
	PhoneTypeOther  PhoneType = "OUTRO"
)

type Email struct {
	IsMain bool   `json:"is_main"`
	Email  string `json:"email"`
}

type PersonalQualification struct {
	ID                    uuid.UUID       `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	OccupationCode        *OccupationCode `json:"occupation_code,omitempty"`
	OccupationDescription *string         `json:"occupation_description,omitempty"`
	Income                *Income         `json:"income,omitempty"`
	Patrimony             *Patrimony      `json:"patrimony,omitempty"`

	OrgID     string
	CrossOrg  bool
	CreatedAt timeutil.DateTime
	UpdatedAt timeutil.DateTime
}

type OccupationCode string

const (
	OccupationCodeReceitaFederal OccupationCode = "RECEITA_FEDERAL"
	OccupationCodeCBO            OccupationCode = "CBO"
	OccupationCodeOther          OccupationCode = "OUTRO"
)

type Income struct {
	Frequency IncomeFrequency     `json:"frequency"`
	Amount    string              `json:"amount"`
	Currency  string              `json:"currency"`
	Date      timeutil.BrazilDate `json:"date"`
}

type IncomeFrequency string

const (
	IncomeFrequencyDaily      IncomeFrequency = "DIARIA"
	IncomeFrequencyWeekly     IncomeFrequency = "SEMANAL"
	IncomeFrequencyFortnight  IncomeFrequency = "QUINZENAL"
	IncomeFrequencyMonthly    IncomeFrequency = "MENSAL"
	IncomeFrequencyBimonthly  IncomeFrequency = "BIMESTRAL"
	IncomeFrequencyQuarterly  IncomeFrequency = "TRIMESTRAL"
	IncomeFrequencySemiannual IncomeFrequency = "SEMESTRAL"
	IncomeFrequencyAnnual     IncomeFrequency = "ANNUAL"
	IncomeFrequencyOther      IncomeFrequency = "OUTROS"
)

type Patrimony struct {
	Amount   string `json:"amount"`
	Currency string `json:"currency"`
	Year     int    `json:"year"`
}

type PersonalFinancialRelation struct {
	ID                           uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	StartDate                    timeutil.BrazilDate
	ProductServiceTypes          []ProductServiceType `gorm:"serializer:json"`
	ProductServiceAdditionalInfo *string
	Procurators                  []Procurator        `gorm:"serializer:json"`
	SalaryPortabilities          []SalaryPortability `gorm:"serializer:json"`
	PaycheckBankLinks            []PaycheckBankLink  `gorm:"serializer:json"`

	OrgID     string
	CrossOrg  bool
	CreatedAt timeutil.DateTime
	UpdatedAt timeutil.DateTime
}

type ProductServiceType string

const (
	ProductServiceTypeCheckingAccount   ProductServiceType = "CONTA_DEPOSITO_A_VISTA"
	ProductServiceTypeSavingsAccount    ProductServiceType = "CONTA_POUPANCA"
	ProductServiceTypePrePaidCard       ProductServiceType = "CONTA_PAGAMENTO_PRE_PAGA"
	ProductServiceTypeCreditCard        ProductServiceType = "CARTAO_CREDITO"
	ProductServiceTypeCreditOperation   ProductServiceType = "OPERACAO_CREDITO"
	ProductServiceTypeInsurance         ProductServiceType = "SEGURO"
	ProductServiceTypePension           ProductServiceType = "PREVIDENCIA"
	ProductServiceTypeInvestment        ProductServiceType = "INVESTIMENTO"
	ProductServiceTypeExchangeOperation ProductServiceType = "OPERACOES_CAMBIO"
)

type Procurator struct {
	Type       ProcuratorType `json:"type"`
	CPF        string
	CivilName  string
	SocialName *string
}

type ProcuratorType string

const (
	ProcuratorTypeLegalRepresentative ProcuratorType = "REPRESENTANTE_LEGAL"
	ProcuratorTypeProcurator          ProcuratorType = "PROCURADOR"
)

type SalaryPortability struct {
	EmployerName             string              `json:"employer_name"`
	EmployerCPFCNPJ          string              `json:"employer_cpf_cnpj"`
	PaycheckBankDetainerCNPJ string              `json:"paycheck_bank_detainer_cnpj"`
	PaycheckBankDetainerISPB string              `json:"paycheck_bank_detainer_ispb"`
	ApprovedAt               timeutil.BrazilDate `json:"approved_at"`
}

type PaycheckBankLink struct {
	EmployerName     string              `json:"employer_name"`
	EmployerCPFCNPJ  string              `json:"employer_cpf_cnpj"`
	PaycheckBankCNPJ string              `json:"paycheck_bank_cnpj"`
	PaycheckBankISPB string              `json:"paycheck_bank_ispb"`
	OpenedAt         timeutil.BrazilDate `json:"opened_at"`
}
