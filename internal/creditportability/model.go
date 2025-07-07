package creditportability

import (
	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/mock-bank/internal/creditop"
	"github.com/luikyv/mock-bank/internal/timeutil"
)

var (
	Scope = goidc.NewScope("credit-portability")
)

type Portability struct {
	ID                                  uuid.UUID
	Status                              Status
	StatusUpdatedAt                     timeutil.DateTime
	ContractID                          uuid.UUID
	Contract                            *creditop.Contract
	CustomerContacts                    []Contact
	InstitutionName                     string
	InstitutionCNPJ                     string
	InstitutionContacts                 *[]Contact
	InterestRates                       []creditop.InterestRate  `gorm:"serializer:json"`
	Fees                                []creditop.Fee           `gorm:"serializer:json"`
	FinanceCharges                      []creditop.FinanceCharge `gorm:"serializer:json"`
	CET                                 string                   `gorm:"column:cet"`
	AmortizationSchedule                creditop.AmortizationSchedule
	AmortizationScheduledAdditionalInfo *string
	DigitalSignatureProof               string
	InstalmentPeriodicity               Periodicity
	TotalInstalments                    int
	InstalmentAmount                    string
	InstalmentCurrency                  string
	DueDate                             timeutil.BrazilDate

	OrgID     string
	CreatedAt timeutil.DateTime
	UpdatedAt timeutil.DateTime
}

type Status string

const (
	StatusReceived                     Status = "RECEBIDO"
	StatusPending                      Status = "PENDENTE"
	StatusAcceptedSettlementInProgress Status = "ACORDO_DE_LIQUIDACAO_EM_ANDAMENTO"
	StatusAcceptedSettlementCompleted  Status = "ACORDO_DE_LIQUIDACAO_CONCLUIDO"
	StatusPortabilityCompleted         Status = "PORTABILIDADE_CONCLUIDA"
	StatusRejected                     Status = "REJEITADO"
	StatusCancelled                    Status = "CANCELADO"
	StatusPaymentIssue                 Status = "PROBLEMA_DE_PAGAMENTO"
)

type Contact struct {
	Type  ContactType
	Value string
}

type ContactType string

const (
	ContactTypePhone ContactType = "TELEFONE"
	ContactTypeEmail ContactType = "EMAIL"
)

type Periodicity string

const (
	PeriodicityIrregular  Periodicity = "SEM_PERIODICIDADE_REGULAR"
	PeriodicityDaily      Periodicity = "DIARIO"
	PeriodicityWeekly     Periodicity = "SEMANAL"
	PeriodicityBiweekly   Periodicity = "QUINZENAL"
	PeriodicityMonthly    Periodicity = "MENSAL"
	PeriodicityBimonthly  Periodicity = "BIMESTRAL"
	PeriodicityQuarterly  Periodicity = "TRIMESTRAL"
	PeriodicitySemiannual Periodicity = "SEMESTRAL"
	PeriodicityAnnual     Periodicity = "ANNUAL"
)

type Eligibility struct {
	IsEligible                        bool
	IneligibilityReason               *IneligibilityReason
	IneligibilityReasonAdditionalInfo *string
	Status                            *EligibilityStatus
	StatusUpdatedAt                   *timeutil.DateTime
	Channel                           *Channel
	CompanyName                       *string
	CompanyCNPJ                       *string
}

type EligibilityStatus string

const (
	EligibilityStatusAvailable  EligibilityStatus = "DISPONIVEL"
	EligibilityStatusInProgress EligibilityStatus = "EM_ANDAMENTO"
)

type Channel string

const (
	ChannelOFB       Channel = "OFB"
	ChannelRegistrar Channel = "REGISTRADORA"
)

type IneligibilityReason string

const (
	IneligibilityReasonContractLiquidated IneligibilityReason = "CONTRATO_LIQUIDADO"
	IneligibilityReasonJudicialAction     IneligibilityReason = "CLIENTE_COM_ACAO_JUDICIAL"
	IneligibilityReasonIncompatibleMode   IneligibilityReason = "MODALIDADE_OPERACAO_INCOMPATIVEL"
	IneligibilityReasonOther              IneligibilityReason = "OUTROS"
)
