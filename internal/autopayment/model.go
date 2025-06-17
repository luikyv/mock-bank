package autopayment

import (
	"strings"

	"github.com/google/uuid"
	"github.com/luiky/mock-bank/internal/account"
	"github.com/luiky/mock-bank/internal/consent"
	"github.com/luiky/mock-bank/internal/payment"
	"github.com/luiky/mock-bank/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

var (
	ScopeConsentID = goidc.NewDynamicScope("recurring-consent", func(requestedScope string) bool {
		return strings.HasPrefix(requestedScope, "recurring-consent:")
	})
	Scope = goidc.NewScope("recurring-payments")
)

type Payment struct {
	ID                        uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	ConsentID                 uuid.UUID
	EndToEndID                string
	Date                      timeutil.BrazilDate
	Status                    payment.Status
	StatusUpdatedAt           timeutil.DateTime
	Amount                    string
	Currency                  string
	CreditorAccountISBP       string
	CreditorAccountIssuer     *string
	CreditorAccountNumber     string
	CreditorAccountType       payment.AccountType
	RemittanceInformation     *string
	CNPJInitiator             string
	IBGETownCode              *string
	AuthorisationFlow         *payment.AuthorisationFlow
	LocalInstrument           payment.LocalInstrument
	Proxy                     *string
	TransactionIdentification *string
	DocumentIdentification    string
	DocumentRel               payment.Relation
	OriginalID                *uuid.UUID
	Reference                 *string
	ClientID                  string
	DebtorAccountID           *uuid.UUID `gorm:"column:account_id"`
	DebtorAccount             *account.Account
	// TODO: Should I flatten these fields?
	Rejection    *Rejection            `gorm:"serializer:json"`
	Cancellation *payment.Cancellation `gorm:"serializer:json"`

	OrgID     string
	CreatedAt timeutil.DateTime
	UpdatedAt timeutil.DateTime
}

func (Payment) TableName() string {
	return "recurring_payments"
}

type Consent struct {
	ID              uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	Status          ConsentStatus
	StatusUpdatedAt timeutil.DateTime
	AuthorizedAt    *timeutil.DateTime
	ApprovalDueAt   *timeutil.BrazilDate
	ExpiresAt       *timeutil.DateTime
	UserID          uuid.UUID
	UserCPF         string
	BusinessCNPJ    *string
	Creditors       []Creditor `gorm:"serializer:json"`
	AdditionalInfo  *string
	Configuration   Configuration `gorm:"serializer:json"`
	DebtorAccountID *uuid.UUID    `gorm:"column:account_id"`
	DebtorAccount   *account.Account
	Rejection       *ConsentRejection  `gorm:"serializer:json"`
	Revocation      *ConsentRevocation `gorm:"serializer:json"`
	ClientID        string

	OrgID     string
	CreatedAt timeutil.DateTime
	UpdatedAt timeutil.DateTime
}

func (Consent) TableName() string {
	return "recurring_consents"
}

func (c Consent) URN() string {
	return consent.URN(c.ID)
}

type ConsentStatus string

const (
	ConsentStatusAwaitingAuthorization ConsentStatus = "AWAITING_AUTHORISATION"
	ConsentStatusAuthorized            ConsentStatus = "AUTHORISED"
	ConsentStatusRejected              ConsentStatus = "REJECTED"
	ConsentStatusRevoked               ConsentStatus = "REVOKED"
	ConsentStatusPartiallyAccepted     ConsentStatus = "PARTIALLY_ACCEPTED"
	ConsentStatusConsumed              ConsentStatus = "CONSUMED"
)

type Configuration struct {
	Automatic *struct {
		ContractID            string   `json:"contractId"`
		FixedAmount           *string  `json:"fixedAmount,omitempty"`
		MaximumVariableAmount *string  `json:"maximumVariableAmount,omitempty"`
		Interval              Interval `json:"interval"`
		ContractDebtor        struct {
			Name     string           `json:"name"`
			Document payment.Document `json:"document"`
		} `json:"contractDebtor,omitempty"`
		FirstPayment *struct {
			Type                  payment.Type        `json:"type"`
			Date                  timeutil.BrazilDate `json:"date"`
			Currency              string              `json:"currency"`
			Amount                string              `json:"amount"`
			RemittanceInformation string              `json:"remittanceInformation,omitempty"`
			CreditorAccount       payment.Account     `json:"creditorAccount"`
		} `json:"firstPayment,omitempty"`
		MinimumVariableAmount *string             `json:"minimumVariableAmount,omitempty"`
		IsRetryAccepted       bool                `json:"isRetryAccepted"`
		UseOverdraftLimit     bool                `json:"useOverdraftLimit"`
		ReferenceStartDate    timeutil.BrazilDate `json:"referenceStartDate"`
	} `json:"automatic,omitempty"`
	Sweeping *struct {
		TotalAllowedAmount *string            `json:"totalAllowedAmount,omitempty"`
		TransactionLimit   *string            `json:"transactionLimit,omitempty"`
		PeriodicLimits     *PeriodicLimits    `json:"periodicLimits,omitempty"`
		UseOverdraftLimit  bool               `json:"useOverdraftLimit"`
		StartDateTime      *timeutil.DateTime `json:"startDateTime"`
	} `json:"sweeping,omitempty"`
	VRP *struct {
		TransactionLimit *string         `json:"transactionLimit,omitempty"`
		GlobalLimits     *Limit          `json:"globalLimits,omitempty"`
		PeriodicLimits   *PeriodicLimits `json:"periodicLimits,omitempty"`
	} `json:"vrp,omitempty"`
}

type Interval string

const (
	IntervalWeekly     Interval = "SEMANAL"
	IntervalMonthly    Interval = "MENSAL"
	IntervalAnnually   Interval = "ANUAL"
	IntervalSemiannual Interval = "SEMESTRAL"
	IntervalQuarterly  Interval = "TRIMESTRAL"
)

type PeriodicLimits struct {
	Day   *Limit `json:"day,omitempty"`
	Week  *Limit `json:"week,omitempty"`
	Month *Limit `json:"month,omitempty"`
	Year  *Limit `json:"year,omitempty"`
}

type Limit struct {
	Quantity         *int    `json:"quantityLimit"`
	TransactionLimit *string `json:"transactionLimit,omitempty"`
}

type Rejection struct {
	Code   RejectionReasonCode `json:"code"`
	Detail string              `json:"detail"`
}

type RejectionReasonCode string

const (
	RejectionInsufficientBalance            RejectionReasonCode = "SALDO_INSUFICIENTE"
	RejectionExceedsLimit                   RejectionReasonCode = "VALOR_ACIMA_LIMITE"
	RejectionInvalidAmount                  RejectionReasonCode = "VALOR_INVALIDO"
	RejectionNotInformed                    RejectionReasonCode = "NAO_INFORMADO"
	RejectionPaymentConsentMismatch         RejectionReasonCode = "PAGAMENTO_DIVERGENTE_CONSENTIMENTO"
	RejectionRefusedByHolder                RejectionReasonCode = "PAGAMENTO_RECUSADO_DETENTORA"
	RejectionRefusedBySPI                   RejectionReasonCode = "PAGAMENTO_RECUSADO_SPI"
	RejectionInvalidConsent                 RejectionReasonCode = "CONSENTIMENTO_INVALIDO"
	RejectionSPIFailure                     RejectionReasonCode = "FALHA_INFRAESTRUTURA_SPI"
	RejectionICPFailure                     RejectionReasonCode = "FALHA_INFRAESTRUTURA_ICP"
	RejectionReceiverPSPFailure             RejectionReasonCode = "FALHA_INFRAESTRUTURA_PSP_RECEBEDOR"
	RejectionHolderInstitutionFailure       RejectionReasonCode = "FALHA_INFRAESTRUTURA_DETENTORA"
	RejectionPeriodValueLimitExceeded       RejectionReasonCode = "LIMITE_PERIODO_VALOR_EXCEDIDO"
	RejectionPeriodQuantityLimitExceeded    RejectionReasonCode = "LIMITE_PERIODO_QUANTIDADE_EXCEDIDO"
	RejectionInconsistentOwnership          RejectionReasonCode = "TITULARIDADE_INCONSISTENTE"
	RejectionTotalConsentValueLimitExceeded RejectionReasonCode = "LIMITE_VALOR_TOTAL_CONSENTIMENTO_EXCEDIDO"
	RejectionTransactionValueLimitExceeded  RejectionReasonCode = "LIMITE_VALOR_TRANSACAO_CONSENTIMENTO_EXCEDIDO" // O valor da transação ultrapassar o limite de valor por transação
	RejectionRevokedConsent                 RejectionReasonCode = "CONSENTIMENTO_REVOGADO"
	RejectionAttemptLimitExceeded           RejectionReasonCode = "LIMITE_TENTATIVAS_EXCEDIDO"
	RejectionOutOfAllowedPeriod             RejectionReasonCode = "FORA_PRAZO_PERMITIDO"
	RejectionInvalidAttemptDetail           RejectionReasonCode = "DETALHE_TENTATIVA_INVALIDO"
	RejectionInvalidPaymentDetail           RejectionReasonCode = "DETALHE_PAGAMENTO_INVALIDO"
)

type ConsentRejection struct {
	By     TerminatedBy         `json:"by"`
	From   TerminatedFrom       `json:"from"`
	Code   ConsentRejectionCode `json:"code"`
	Detail string               `json:"detail"`
}

type ConsentRejectionCode string

const (
	ConsentRejectionNotProvided                 ConsentRejectionCode = "NAO_INFORMADO"
	ConsentRejectionInfrastructureFailure       ConsentRejectionCode = "FALHA_INFRAESTRUTURA"
	ConsentRejectionAuthorizationTimeout        ConsentRejectionCode = "TEMPO_EXPIRADO_AUTORIZACAO"
	ConsentRejectionRejectedByUser              ConsentRejectionCode = "REJEITADO_USUARIO"
	ConsentRejectionSourceAndTargetAccountsSame ConsentRejectionCode = "CONTAS_ORIGEM_DESTINO_IGUAIS"
	ConsentRejectionAccountDoesNotAllowPayment  ConsentRejectionCode = "CONTA_NAO_PERMITE_PAGAMENTO"
	ConsentRejectionInsufficientFunds           ConsentRejectionCode = "SALDO_INSUFICIENTE"
	ConsentRejectionAmountAboveLimit            ConsentRejectionCode = "VALOR_ACIMA_LIMITE"
	ConsentRejectionInvalidQRCode               ConsentRejectionCode = "AUTENTICACAO_DIVERGENTE"
)

type ConsentRevocation struct {
	By     TerminatedBy          `json:"by"`
	From   TerminatedFrom        `json:"from"`
	Code   ConsentRevocationCode `json:"code"`
	Detail string                `json:"detail"`
}

type ConsentRevocationCode string

const (
	ConsentRevocationNotProvided ConsentRevocationCode = "NAO_INFORMADO"
	ConsentRevocationByUser      ConsentRevocationCode = "REVOGADO_USUARIO"
	ConsentRevocationByCreditor  ConsentRevocationCode = "REVOGADO_RECEBEDOR"
)

type TerminatedFrom string

const (
	TerminatedFromInitiator TerminatedFrom = "INICIADORA"
	TerminatedFromHolder    TerminatedFrom = "DETENTORA"
)

type TerminatedBy string

const (
	TerminatedByInitiator TerminatedBy = "INICIADORA"
	TerminatedByHolder    TerminatedBy = "DETENTORA"
	TerminatedByUser      TerminatedBy = "USUARIO"
)

type Creditor struct {
	Type    payment.CreditorType `json:"type"`
	CPFCNPJ string               `json:"cpf_cnpj"`
	Name    string               `json:"name"`
}
