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
	ID                                          uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	ConsentID                                   uuid.UUID
	Status                                      Status
	StatusUpdatedAt                             timeutil.DateTime
	ContractID                                  uuid.UUID
	ContractNumber                              string
	ContractIPOCCode                            string `gorm:"column:contract_ipoc_code"`
	Contract                                    *creditop.Contract
	CustomerContacts                            []Contact `gorm:"serializer:json"`
	CreditorInstitutionName                     string
	CreditorInstitutionCNPJ                     string
	ProposingInstitutionName                    string
	ProposingInstitutionCNPJ                    string
	ProposingInstitutionContacts                *[]Contact               `gorm:"serializer:json"`
	ProposedInterestRates                       []creditop.InterestRate  `gorm:"serializer:json"`
	ProposedFees                                []creditop.Fee           `gorm:"serializer:json"`
	ProposedFinanceCharges                      []creditop.FinanceCharge `gorm:"serializer:json"`
	ProposedCET                                 string                   `gorm:"column:proposed_cet"`
	ProposedAmortizationSchedule                creditop.AmortizationSchedule
	ProposedAmortizationScheduledAdditionalInfo *string
	DigitalSignatureProofDocumentID             string
	DigitalSignatureProofSignedAt               string
	ProposedInstalmentPeriodicity               creditop.Periodicity
	ProposedTotalInstalments                    int
	ProposedInstalmentAmount                    string
	ProposedInstalmentCurrency                  string
	ProposedAmount                              string
	ProposedCurrency                            string
	ProposedDueDate                             string
	ClientID                                    string
	Rejection                                   *Rejection             `gorm:"serializer:json"`
	LoanSettlementInstruction                   *SettlementInstruction `gorm:"serializer:json"`
	StatusReason                                *StatusReason          `gorm:"serializer:json"`
	Payment                                     *Payment               `gorm:"serializer:json"`

	OrgID     string
	CreatedAt timeutil.DateTime
	UpdatedAt timeutil.DateTime
}

func (Portability) TableName() string {
	return "credit_portabilities"
}

type Status string

const (
	StatusReceived                     Status = "RECEIVED"
	StatusPending                      Status = "PENDING"
	StatusAcceptedSettlementInProgress Status = "ACCEPTED_SETTLEMENT_IN_PROGRESS"
	StatusAcceptedSettlementCompleted  Status = "ACCEPTED_SETTLEMENT_COMPLETED"
	StatusPortabilityCompleted         Status = "PORTABILITY_COMPLETED"
	StatusRejected                     Status = "REJECTED"
	StatusCancelled                    Status = "CANCELLED"
	StatusPaymentIssue                 Status = "PAYMENT_ISSUE"
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

type Eligibility struct {
	ID                                uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	IsEligible                        bool
	IneligibilityReason               *IneligibilityReason
	IneligibilityReasonAdditionalInfo *string
	Status                            *EligibilityStatus
	StatusUpdatedAt                   *timeutil.DateTime
	Channel                           *Channel
	CompanyName                       *string
	CompanyCNPJ                       *string
	ContractID                        uuid.UUID

	OrgID     string
	CrossOrg  bool
	CreatedAt timeutil.DateTime
	UpdatedAt timeutil.DateTime
}

func (e Eligibility) TableName() string {
	return "credit_portability_eligibilities"
}

type EligibilityStatus string

const (
	EligibilityStatusAvailable  EligibilityStatus = "DISPONIVEL"
	EligibilityStatusInProgress EligibilityStatus = "EM_ANDAMENTO"
)

type IneligibilityReason string

const (
	IneligibilityReasonContractLiquidated IneligibilityReason = "CONTRATO_LIQUIDADO"
	IneligibilityReasonJudicialAction     IneligibilityReason = "CLIENTE_COM_ACAO_JUDICIAL"
	IneligibilityReasonIncompatibleMode   IneligibilityReason = "MODALIDADE_OPERACAO_INCOMPATIVEL"
	IneligibilityReasonOther              IneligibilityReason = "OUTROS"
)

type Channel string

const (
	ChannelOFB       Channel = "OFB"
	ChannelRegistrar Channel = "REGISTRADORA"
)

type Rejection struct {
	Reason         RejectionReason `json:"rejectionReason"`
	By             RejectedBy      `json:"rejectedBy"`
	AdditionalInfo *string         `json:"rejectionAdditionalInfo"`
}

type RejectedBy string

const (
	RejectedByProposer RejectedBy = "PROPONENTE"
	RejectedByUser     RejectedBy = "USUARIO"
	RejectedByCreditor RejectedBy = "CREDORA"
)

type RejectionReason string

const (
	RejectionReasonCanceledByClient         RejectionReason = "CANCELADO_PELO_CLIENTE"
	RejectionReasonDivergentDebt            RejectionReason = "SALDO_DEVEDOR_ATUALIZADO_SUBSTANCIALMENTE_DIVERGENTE"
	RejectionReasonCreditPolicy             RejectionReason = "POLITICA_DE_CREDITO"
	RejectionReasonRetentionOfClient        RejectionReason = "RETENCAO_DO_CLIENTE"
	RejectionReasonContractLiquidated       RejectionReason = "CONTRATO_JA_LIQUIDADO"
	RejectionReasonPaymentDiscrepancy       RejectionReason = "DIVERGENCIA_DE_PAGAMENTO_EFETUADO"
	RejectionReasonPaymentDue               RejectionReason = "DECURSO_DO_PRAZO_PARA_PAGAMENTO"
	RejectionReasonPortabilityNotLiquidated RejectionReason = "PORTABILIDADE_CANCELADA_POR_FALTA_DE_LIQUIDACAO"
	RejectionReasonPortabilityInProgress    RejectionReason = "PORTABILIDADE_EM_ANDAMENTO"
	RejectionReasonLegalAction              RejectionReason = "CLIENTE_COM_ACAO_JUDICIAL"
	RejectionReasonIncompatibleOperation    RejectionReason = "MODALIDADE_DA_OPERACAO_INCOMPATIVEL"
	RejectionReasonOther                    RejectionReason = "OUTROS"
)

type SettlementInstruction struct {
	Amount        string            `json:"settlementAmount"`
	Currency      string            `json:"currency"`
	DateTime      timeutil.DateTime `json:"settlementDateTime"`
	TransactionID string            `json:"transactionId"`
}

type StatusReason struct {
	ReasonType               *RejectionReason `json:"reasonType"`
	ReasonTypeAdditionalInfo *string          `json:"reasonTypeAdditionalInfo"`
	DigitalSignatureProof    *struct {
		DocumentID        string `json:"documentId"`
		SignatureDateTime string `json:"signatureDateTime"`
	} `json:"digitalSignatureProof"`
}

type AccountData struct {
	Number string
}

type Query struct {
	ID           string
	ContractID   string
	ConsentID    string
	Statuses     []Status
	LoadContract bool
}

type Payment struct {
	PortabilityID string            `json:"portabilityId"`
	DateTime      timeutil.DateTime `json:"paymentDateTime"`
	Amount        string            `json:"amount"`
	Currency      string            `json:"currency"`
	TransactionID string            `json:"transactionId"`
}
