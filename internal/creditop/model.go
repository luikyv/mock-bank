package creditop

import (
	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/mock-bank/internal/resource"
	"github.com/luikyv/mock-bank/internal/timeutil"
)

var (
	ScopeLoans = goidc.NewScope("loans")
)

type ConsentContract struct {
	ConsentID  uuid.UUID
	ContractID uuid.UUID
	OwnerID    uuid.UUID
	Status     resource.Status
	Type       resource.Type
	Contract   *Contract

	OrgID     string
	CreatedAt timeutil.DateTime
	UpdatedAt timeutil.DateTime
}

func (ConsentContract) TableName() string {
	return "consent_credit_contracts"
}

type Contract struct {
	ID                                  uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	Type                                resource.Type
	Number                              string
	CompanyCNPJ                         string `gorm:"column:company_cnpj"`
	IPOCCode                            string `gorm:"column:ipoc_code"`
	ProductName                         string
	ProductType                         ProductType
	ProductSubType                      ProductSubType          `gorm:"column:product_subtype"`
	ProductSubTypeCategory              *ProductSubTypeCategory `gorm:"column:product_subtype_category"`
	Date                                timeutil.BrazilDate
	DisbursementDates                   *[]timeutil.BrazilDate `gorm:"serializer:json"`
	SettlementDate                      *timeutil.BrazilDate
	Amount                              string
	Currency                            *string
	DueDate                             *timeutil.BrazilDate
	InstalmentPeriodicity               Periodicity
	InstalmentPeriodicityAdditionalInfo *string
	FirstInstalmentDueDate              *timeutil.BrazilDate
	NextInstalmentAmount                *string
	CET                                 string `gorm:"column:cet"` // Total Effective Cost rate.
	AmortizationSchedule                AmortizationSchedule
	AmortizationScheduleAdditionalInfo  *string
	CNPJConsignee                       *string         `gorm:"column:cnpj_consignee"`
	InterestRates                       []InterestRate  `gorm:"serializer:json"`
	ContractedFees                      []Fee           `gorm:"serializer:json"`
	FinanceCharges                      []FinanceCharge `gorm:"serializer:json"`
	OwnerID                             uuid.UUID
	OutstandingBalance                  string
	OutstandingBalanceUpdatedAt         *timeutil.DateTime
	PaidInstalments                     *int
	DueInstalments                      int
	PastDueInstalments                  int
	TotalInstalments                    *int
	TotalInstalmentType                 InstalmentPeriodicityTotal
	RemainingInstalments                *int
	HasInsuranceContracted              *bool
	// This should be DIA, SEMANA, MES, ANO, SEM_PRAZO_REMANESCENTE.
	RemainingInstalmentType InstalmentPeriodicityRemaining
	TotalRemainingAmount    *string

	OrgID     string
	CrossOrg  bool
	CreatedAt timeutil.DateTime
	UpdatedAt timeutil.DateTime
}

func (Contract) TableName() string {
	return "credit_contracts"
}

func (c *Contract) Contract() *Contract {
	return c
}

type ProductType string

const (
	ProductTypeLoan ProductType = "EMPRESTIMOS"
)

type ProductSubType string

const (
	ProductSubTypeHomeEquity                        ProductSubType = "HOME_EQUITY"
	ProductSubTypeSpecialCheck                      ProductSubType = "CHEQUE_ESPECIAL"
	ProductSubTypeGuaranteedAccount                 ProductSubType = "CONTA_GARANTIDA"
	ProductSubTypeRotativeCapital                   ProductSubType = "CAPITAL_GIRO_TETO_ROTATIVO"
	ProductSubTypePersonalLoanWithoutConsignment    ProductSubType = "CREDITO_PESSOAL_SEM_CONSIGNACAO"
	ProductSubTypePersonalLoanWithConsignment       ProductSubType = "CREDITO_PESSOAL_COM_CONSIGNACAO"
	ProductSubTypeMicrocreditProductiveOriented     ProductSubType = "MICROCREDITO_PRODUTIVO_ORIENTADO"
	ProductSubTypeWorkingCapitalMaturityUpTo365Days ProductSubType = "CAPITAL_GIRO_PRAZO_VENCIMENTO_ATE_365_DIAS"
	ProductSubTypeWorkingCapitalMaturityOver365Days ProductSubType = "CAPITAL_GIRO_PRAZO_VENCIMENTO_SUPERIOR_365_DIAS"
)

type ProductSubTypeCategory string

const (
	ProductSubTypeCategoryPersonal  ProductSubTypeCategory = "CREDITO_PESSOAL_CLEAN"
	ProductSubTypeCategoryConsigned ProductSubTypeCategory = "CONSIGNADO_SIAPE"
	ProductSubTypeCategoryOther     ProductSubTypeCategory = "OUTRO"
)

type Periodicity string

const (
	PeriodicityIrregular  Periodicity = "SEM_PERIODICIDADE_REGULAR"
	PeriodicityWeekly     Periodicity = "SEMANAL"
	PeriodicityBiweekly   Periodicity = "QUINZENAL"
	PeriodicityMonthly    Periodicity = "MENSAL"
	PeriodicityBimonthly  Periodicity = "BIMESTRAL"
	PeriodicityQuarterly  Periodicity = "TRIMESTRAL"
	PeriodicitySemiannual Periodicity = "SEMESTRAL"
	PeriodicityAnnual     Periodicity = "ANNUAL"
	PeriodicityOther      Periodicity = "OUTROS"
)

type AmortizationSchedule string

const (
	AmortizationScheduleSAC            AmortizationSchedule = "SAC"
	AmortizationSchedulePRICE          AmortizationSchedule = "PRICE"
	AmortizationScheduleSAM            AmortizationSchedule = "SAM"
	AmortizationScheduleNoAmortization AmortizationSchedule = "SEM_SISTEMA_AMORTIZACAO"
	AmortizationScheduleOther          AmortizationSchedule = "OUTROS"
)

type InterestRate struct {
	Type                      InterestRateType    `json:"interestRateType"`
	TaxType                   TaxType             `json:"taxType"`
	TaxPeriodicity            TaxPeriodicity      `json:"taxPeriodicity"`
	Calculation               Calculation         `json:"calculation"`
	RateIndexerType           RateIndexerType     `json:"rateIndexerType"`
	RateIndexerSubType        *RateIndexerSubType `json:"rateIndexerSubType,omitempty"`
	RateIndexerAdditionalInfo *string             `json:"rateIndexerAdditionalInfo,omitempty"`
	FixedRate                 *string             `json:"fixedRate,omitempty"`
	PostFixedRate             *string             `json:"postFixedRate,omitempty"`
	AdditionalInfo            *string             `json:"additionalInfo,omitempty"`
}

type TaxType string

const (
	TaxTypeNominal   TaxType = "NOMINAL"
	TaxTypeEffective TaxType = "EFETIVA"
)

type InterestRateType string

const (
	InterestRateTypeSimple   InterestRateType = "SIMPLES"
	InterestRateTypeCompound InterestRateType = "COMPOSTO"
)

type TaxPeriodicity string

const (
	TaxPeriodicityAM TaxPeriodicity = "AM"
	TaxPeriodicityAA TaxPeriodicity = "AA"
)

type Calculation string

const (
	CalculationBusinessDays Calculation = "21/252"
	Calculation30Day360     Calculation = "30/360"
	Calculation30Day365     Calculation = "30/365"
)

type RateIndexerType string

const (
	RateIndexerTypeNone      RateIndexerType = "SEM_TIPO_INDEXADOR"
	RateIndexerTypeFixed     RateIndexerType = "PRE_FIXADO"
	RateIndexerTypePostFixed RateIndexerType = "POS_FIXADO"
	RateIndexerTypeFloating  RateIndexerType = "FLUTUANTES"
	RateIndexerTypePrice     RateIndexerType = "INDICES_PRECOS"
	RateIndexerTypeRural     RateIndexerType = "CREDITO_RURAL"
	RateIndexerTypeOther     RateIndexerType = "OUTROS_INDEXADORES"
)

type RateIndexerSubType string

const (
	RateIndexerSubTypeNone           RateIndexerSubType = "SEM_SUB_TIPO_INDEXADOR"
	RateIndexerSubTypeFixed          RateIndexerSubType = "PRE_FIXADO"
	RateIndexerSubTypeTRTBF          RateIndexerSubType = "TR_TBF"
	RateIndexerSubTypeTJLP           RateIndexerSubType = "TJLP"
	RateIndexerSubTypeLIBOR          RateIndexerSubType = "LIBOR"
	RateIndexerSubTypeTLP            RateIndexerSubType = "TLP"
	RateIndexerSubTypeOtherPostFixed RateIndexerSubType = "OUTRAS_TAXAS_POS_FIXADAS"
	RateIndexerSubTypeCDI            RateIndexerSubType = "CDI"
	RateIndexerSubTypeSELIC          RateIndexerSubType = "SELIC"
	RateIndexerSubTypeOtherFloating  RateIndexerSubType = "OUTRAS_TAXAS_FLUTUANTES"
	RateIndexerSubTypeIGPM           RateIndexerSubType = "IGPM"
	RateIndexerSubTypeIPCA           RateIndexerSubType = "IPCA"
	RateIndexerSubTypeIPCC           RateIndexerSubType = "IPCC"
	RateIndexerSubTypeOtherPrice     RateIndexerSubType = "OUTROS_INDICES_PRECO"
	RateIndexerSubTypeTCRPre         RateIndexerSubType = "TCR_PRE"
	RateIndexerSubTypeTCRPos         RateIndexerSubType = "TCR_POS"
	RateIndexerSubTypeTRFCPre        RateIndexerSubType = "TRFC_PRE"
	RateIndexerSubTypeTRFCPos        RateIndexerSubType = "TRFC_POS"
	RateIndexerSubTypeOther          RateIndexerSubType = "OUTROS_INDEXADORES"
)

type Fee struct {
	Name              string            `json:"feeName"`
	Code              string            `json:"feeCode"`
	ChargeType        ChargeType        `json:"feeChargeType"`
	ChargeCalculation ChargeCalculation `json:"feeCharge"`
	Amount            *string           `json:"feeAmount,omitempty"`
	Rate              *string           `json:"feeRate,omitempty"`
}

type ChargeType string

const (
	ChargeTypeUnique         ChargeType = "UNICA"
	ChargeTypePerInstallment ChargeType = "POR_PARCELA"
)

type ChargeCalculation string

const (
	ChargeCalculationMinimum    ChargeCalculation = "MINIMO"
	ChargeCalculationMaximum    ChargeCalculation = "MAXIMO"
	ChargeCalculationFixed      ChargeCalculation = "FIXO"
	ChargeCalculationPercentage ChargeCalculation = "PERCENTUAL"
)

type FinanceCharge struct {
	Type           FinanceChargeType `json:"chargeType"`
	AdditionalInfo *string           `json:"chargeAdditionalInfo,omitempty"`
	Rate           *string           `json:"chargeRate,omitempty"`
}

type FinanceChargeType string

const (
	FinanceChargeTypeInterestRemuneratoryDelay FinanceChargeType = "JUROS_REMUNERATORIOS_POR_ATRASO"
	FinanceChargeTypeLatePaymentFine           FinanceChargeType = "MULTA_ATRASO_PAGAMENTO"
	FinanceChargeTypeInterestMoratoriumDelay   FinanceChargeType = "JUROS_MORA_ATRASO"
	FinanceChargeTypeIOFContract               FinanceChargeType = "IOF_CONTRATACAO"
	FinanceChargeTypeIOFDelay                  FinanceChargeType = "IOF_POR_ATRASO"
	FinanceChargeTypeNoCharge                  FinanceChargeType = "SEM_ENCARGO"
	FinanceChargeTypeOther                     FinanceChargeType = "OUTROS"
)

type Warranty struct {
	ID         uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	ContractID uuid.UUID
	Currency   string
	Amount     string
	Type       WarrantyType
	SubType    WarrantySubType `gorm:"column:subtype"`

	OrgID     string
	CrossOrg  bool
	CreatedAt timeutil.DateTime
	UpdatedAt timeutil.DateTime
}

func (Warranty) TableName() string {
	return "credit_contract_warranties"
}

type WarrantyType string

const (
	WarrantyTypeCreditorRightsAssignment WarrantyType = "CESSAO_DIREITOS_CREDITORIOS"
	WarrantyTypeBail                     WarrantyType = "CAUCAO"
	WarrantyTypePledge                   WarrantyType = "PENHOR"
	WarrantyTypeFiduciaryAlienation      WarrantyType = "ALIENACAO_FIDUCIARIA"
	WarrantyTypeMortgage                 WarrantyType = "HIPOTECA"
	WarrantyTypeGovernmentGuaranteed     WarrantyType = "OPERACOES_GARANTIDAS_PELO_GOVERNO"
	WarrantyTypeOtherNonSurety           WarrantyType = "OUTRAS_GARANTIAS_NAO_FIDEJUSSORIAS"
	WarrantyTypeInsurance                WarrantyType = "SEGUROS_ASSEMELHADOS"
	WarrantyTypeSurety                   WarrantyType = "GARANTIA_FIDEJUSSORIA"
	WarrantyTypeLeasedAssets             WarrantyType = "BENS_ARRENDADOS"
	WarrantyTypeInternational            WarrantyType = "GARANTIAS_INTERNACIONAIS"
	WarrantyTypeOtherEntitiesGuaranteed  WarrantyType = "OPERACOES_GARANTIDAS_OUTRAS_ENTIDADES"
	WarrantyTypeCompensationAgreements   WarrantyType = "ACORDOS_COMPENSACAO"
)

type WarrantySubType string

const (
	WarrantySubTypeSharesDebentures                   WarrantySubType = "ACOES_DEBENTURES"
	WarrantySubTypeCompensationAgreements             WarrantySubType = "ACORDOS_COMPENSACAO_LIQUIDACAO_OBRIGACOES"
	WarrantySubTypeFixedIncomeInvestments             WarrantySubType = "APLICACOES_FINANCEIRAS_RENDA_FIXA"
	WarrantySubTypeVariableIncomeInvestments          WarrantySubType = "APLICACOES_FINANCEIRAS_RENDA_VARIAVEL"
	WarrantySubTypeExportCreditPolicies               WarrantySubType = "APOLICES_CREDITO_EXPORTACAO"
	WarrantySubTypeCCRReciprocalCredits               WarrantySubType = "CCR_CONVENIO_CREDITOS_RECIPROCOS"
	WarrantySubTypeChecks                             WarrantySubType = "CHEQUES"
	WarrantySubTypeCivil                              WarrantySubType = "CIVIL"
	WarrantySubTypeRentalRights                       WarrantySubType = "DIREITOS_SOBRE_ALUGUEIS"
	WarrantySubTypeFederalPublicSecurities            WarrantySubType = "DEPOSITS_A_VISTA_A_PRAZO_POUPANCA_OURO_TITULOS_PUBLICOS_FEDERAIS_ART_36"
	WarrantySubTypeEntitySecurities                   WarrantySubType = "DEPOSITO_TITULOS_EMITIDOS_ENTIDADES_ART_23"
	WarrantySubTypePromissoryNotes                    WarrantySubType = "DUPLICATES"
	WarrantySubTypeMultilateralDevelopmentEntities    WarrantySubType = "EMD_ENTIDADES_MULTILATERAIS_DESENVOLVIMENTO_ART_37"
	WarrantySubTypeEquipment                          WarrantySubType = "EQUIPAMENTOS"
	WarrantySubTypeStateOrDistrict                    WarrantySubType = "ESTADUAL_OU_DISTRITAL"
	WarrantySubTypeCreditCardInvoice                  WarrantySubType = "FATURA_CARTAO_CREDITO"
	WarrantySubTypeFederal                            WarrantySubType = "FEDERAL"
	WarrantySubTypeFCVSSalaryVariationFund            WarrantySubType = "FCVS_FUNDO_COMPENSACAO_VARIACOES_SALARIAIS"
	WarrantySubTypeFGIIInvestmentGuaranteeFund        WarrantySubType = "FGI_FUNDO_GARANTIDOR_INVESTIMENTOS"
	WarrantySubTypeFGPCCompetitivePromotionFund       WarrantySubType = "FGPC_FUNDO_GARANTIA_PROMOCAO_COMPETIT"
	WarrantySubTypeFGTSServiceTimeFund                WarrantySubType = "FGTS_FUNDO_GARANTIA_TEMPO_SERVICO"
	WarrantySubTypeGuaranteeFundAval                  WarrantySubType = "FUNDO_GARANTIDOR_AVAL"
	WarrantySubTypeFGPCGuaranteeLaw9531               WarrantySubType = "GARANTIA_PRESTADA_FGPC_LEI_9531_ART_37"
	WarrantySubTypeOtherRiskCoverageMechanisms        WarrantySubType = "GARANTIA_PRESTADA_FUNDOS_QUAISQUER_OUTROS_MECANISMOS_COBERTURA_RISCO_CREDITO_ART_37"
	WarrantySubTypeNationalTreasuryOrCentralBank      WarrantySubType = "GARANTIA_PRESTADA_TESOURO_NACIONAL_OU_BACEN_ART_37_BENS_DIREITOS_INTEGRANTES_PATRIMONIO_AFETACAO"
	WarrantySubTypeRealEstate                         WarrantySubType = "IMOVEIS"
	WarrantySubTypeResidentialRealEstate              WarrantySubType = "IMOVEIS_RESIDENCIAIS"
	WarrantySubTypeMitigating                         WarrantySubType = "MITIGADORAS"
	WarrantySubTypeMunicipal                          WarrantySubType = "MUNICIPAL"
	WarrantySubTypeNonMitigating                      WarrantySubType = "NAO_MITIGADORAS"
	WarrantySubTypePromissoryNotesOtherCreditRights   WarrantySubType = "NOTAS_PROMISSORIAS_OUTROS_DIREITOS_CREDITO"
	WarrantySubTypeOthers                             WarrantySubType = "OUTRAS"
	WarrantySubTypeOther                              WarrantySubType = "OUTROS"
	WarrantySubTypeOtherAssets                        WarrantySubType = "OUTROS_BENS"
	WarrantySubTypeOtherDegrees                       WarrantySubType = "OUTROS_GRAUS"
	WarrantySubTypeOtherRealEstate                    WarrantySubType = "OUTROS_IMOVEIS"
	WarrantySubTypeOtherInsurance                     WarrantySubType = "OUTROS_SEGUROS_ASSEMELHADOS"
	WarrantySubTypeIndividual                         WarrantySubType = "PESSOA_FISICA"
	WarrantySubTypeForeignIndividual                  WarrantySubType = "PESSOA_FISICA_EXTERIOR"
	WarrantySubTypeLegalEntity                        WarrantySubType = "PESSOA_JURIDICA"
	WarrantySubTypeForeignLegalEntity                 WarrantySubType = "PESSOA_JURIDICA_EXTERIOR"
	WarrantySubTypeFirstDegreeAssets                  WarrantySubType = "PRIMEIRO_GRAU_BENS_DIREITOS_INTEGRANTES_PATRIMONIO_AFETACAO"
	WarrantySubTypeFirstDegreeResidentialRealEstate   WarrantySubType = "PRIMEIRO_GRAU_IMOVEIS_RESIDENCIAIS"
	WarrantySubTypeFirstDegreeOther                   WarrantySubType = "PRIMEIRO_GRAU_OUTROS"
	WarrantySubTypePROAGRO                            WarrantySubType = "PROAGRO"
	WarrantySubTypeAgriculturalProductsWithWarrant    WarrantySubType = "PRODUTOS_AGROPECUARIOS_COM_WARRANT"
	WarrantySubTypeAgriculturalProductsWithoutWarrant WarrantySubType = "PRODUTOS_AGROPECUARIOS_SEM_WARRANT"
	WarrantySubTypeSBCEExportCreditSociety            WarrantySubType = "SBCE_SOCIEDADE_BRASILEIRA_CREDITO_EXPORTAÇÃO"
	WarrantySubTypeRuralInsurance                     WarrantySubType = "SEGURO_RURAL"
	WarrantySubTypeNoSubType                          WarrantySubType = "SEM_SUB_TIPO_GARANTIA"
	WarrantySubTypeTaxesBudgetRevenues                WarrantySubType = "TRIBUTOS_RECEITAS_ORCAMENTARIAS"
	WarrantySubTypeVehicles                           WarrantySubType = "VEICULOS"
	WarrantySubTypeAutomotiveVehicles                 WarrantySubType = "VEICULOS_AUTOMOTORES"
)

type ReleasePayment struct {
	ID                  uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	ContractID          uuid.UUID
	IsOverParcelPayment bool
	InstalmentID        *string
	Date                timeutil.BrazilDate
	Amount              string
	Currency            string
	OverParcel          *PaymentOverParcel `gorm:"serializer:json"`

	OrgID     string
	CrossOrg  bool
	CreatedAt timeutil.DateTime
	UpdatedAt timeutil.DateTime
}

func (ReleasePayment) TableName() string {
	return "credit_contract_release_payments"
}

type PaymentOverParcel struct {
	Charges []PaymentCharge `json:"charges"`
	Fees    []PaymentFee    `json:"fees"`
}

type PaymentFee struct {
	Name   string `json:"feeName"`
	Code   string `json:"feeCode"`
	Amount string `json:"feeAmount"`
}

type PaymentCharge struct {
	Type           PaymentChargeType `json:"chargeType"`
	AdditionalInfo *string           `json:"chargeAdditionalInfo,omitempty"`
	Amount         string            `json:"chargeAmount"`
}

type PaymentChargeType string

const (
	PaymentChargeTypeInterestRemuneratoryDelay PaymentChargeType = "JUROS_REMUNERATORIOS_POR_ATRASO"
	PaymentChargeTypeLatePaymentFine           PaymentChargeType = "MULTA_ATRASO_PAGAMENTO"
	PaymentChargeTypeInterestMoratoriumDelay   PaymentChargeType = "JUROS_MORA_ATRASO"
	PaymentChargeTypeIOFContract               PaymentChargeType = "IOF_CONTRATACAO"
	PaymentChargeTypeIOFDelay                  PaymentChargeType = "IOF_POR_ATRASO"
	PaymentChargeTypeNoCharge                  PaymentChargeType = "SEM_ENCARGO"
	PaymentChargeTypeOther                     PaymentChargeType = "OUTROS"
)

type BalloonPayment struct {
	ID         uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	ContractID uuid.UUID
	DueDate    timeutil.BrazilDate
	Amount     string
	Currency   string

	OrgID     string
	CrossOrg  bool
	CreatedAt timeutil.DateTime
	UpdatedAt timeutil.DateTime
}

func (BalloonPayment) TableName() string {
	return "credit_contract_balloon_payments"
}

type InstalmentPeriodicityTotal string

const (
	InstalmentPeriodicityTotalDay   InstalmentPeriodicityTotal = "DIA"
	InstalmentPeriodicityTotalWeek  InstalmentPeriodicityTotal = "SEMANA"
	InstalmentPeriodicityTotalMonth InstalmentPeriodicityTotal = "MES"
	InstalmentPeriodicityTotalYear  InstalmentPeriodicityTotal = "ANO"
	InstalmentPeriodicityTotalTotal InstalmentPeriodicityTotal = "SEM_PRAZO_TOTAL"
)

type InstalmentPeriodicityRemaining string

const (
	InstalmentPeriodicityRemainingDay   InstalmentPeriodicityRemaining = "DIA"
	InstalmentPeriodicityRemainingWeek  InstalmentPeriodicityRemaining = "SEMANA"
	InstalmentPeriodicityRemainingMonth InstalmentPeriodicityRemaining = "MES"
	InstalmentPeriodicityRemainingYear  InstalmentPeriodicityRemaining = "ANO"
	InstalmentPeriodicityRemainingTotal InstalmentPeriodicityRemaining = "SEM_PRAZO_REMANESCENTE"
)
