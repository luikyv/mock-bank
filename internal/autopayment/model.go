package autopayment

import (
	"strings"

	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/mock-bank/internal/account"
	"github.com/luikyv/mock-bank/internal/consent"
	"github.com/luikyv/mock-bank/internal/payment"
	"github.com/luikyv/mock-bank/internal/timeutil"
)

const (
	ConsentURNPrefix = "urn:mockbank:recurring-consent:"
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
	EnrollmentID              *uuid.UUID
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
	DocumentRel               consent.Relation
	OriginalID                *uuid.UUID
	Reference                 *string
	RiskSignals               *map[string]any `gorm:"serializer:json"`
	ClientID                  string
	DebtorAccountID           *uuid.UUID `gorm:"column:account_id"`
	DebtorAccount             *account.Account
	Rejection                 *Rejection            `gorm:"serializer:json"`
	Cancellation              *payment.Cancellation `gorm:"serializer:json"`
	Version                   string

	OrgID     string
	CreatedAt timeutil.DateTime
	UpdatedAt timeutil.DateTime
}

func (Payment) TableName() string {
	return "recurring_payments"
}

func (p Payment) PaymentAmount() string {
	return p.Amount
}

type Consent struct {
	ID                         uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	Status                     ConsentStatus
	StatusUpdatedAt            timeutil.DateTime
	AuthorizedAt               *timeutil.DateTime
	ApprovalDueAt              *timeutil.BrazilDate
	ExpiresAt                  *timeutil.DateTime
	UserIdentification         string
	UserRel                    consent.Relation
	BusinessIdentification     *string
	BusinessRel                *consent.Relation
	OwnerID                    uuid.UUID
	Creditors                  []Creditor `gorm:"serializer:json"`
	AdditionalInfo             *string
	Configuration              Configuration   `gorm:"serializer:json"`
	RiskSignals                *map[string]any `gorm:"serializer:json"`
	DebtorAccountID            *uuid.UUID      `gorm:"column:account_id"`
	DebtorAccount              *account.Account
	Rejection                  *ConsentRejection  `gorm:"serializer:json"`
	Revocation                 *ConsentRevocation `gorm:"serializer:json"`
	ClientID                   string
	EnrollmentID               *uuid.UUID
	EnrollmentChallenge        *string
	EnrollmentTransactionLimit *string
	EnrollmentDailyLimit       *string
	Version                    string

	OrgID     string
	CreatedAt timeutil.DateTime
	UpdatedAt timeutil.DateTime
}

func (Consent) TableName() string {
	return "recurring_payment_consents"
}

func (c Consent) URN() string {
	return ConsentURN(c.ID)
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
			Document consent.Document `json:"document"`
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

type ConsentEdition struct {
	RiskSignals *map[string]any `json:"riskSignals,omitempty"`
	Creditors   []struct {
		Name string `json:"name"`
	} `json:"creditors"`
	ExpiresAt              *timeutil.DateTime `json:"expirationDateTime,omitempty"`
	RecurringConfiguration *struct {
		Automatic *struct {
			MaximumVariableAmount *string `json:"maximumVariableAmount,omitempty"`
		} `json:"automatic,omitempty"`
	} `json:"recurringConfiguration,omitempty"`
	LoggedUser     *consent.Document `json:"loggedUser,omitempty"`
	BusinessEntity *consent.Document `json:"businessEntity,omitempty"`
}

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
	ConsentRejectionAuthenticationMismatch                           = "AUTENTICACAO_DIVERGENTE"
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

type Query struct {
	ID        string
	ConsentID string
	Order     string
	// DebtorAccount indicates whether the DebtorAccount will be preloaded.
	DebtorAccount bool
	Statuses      []payment.Status
}

type Filter struct {
	ConsentID    string
	EnrollmentID string
	Statuses     []payment.Status
	From         *timeutil.BrazilDate
	To           *timeutil.BrazilDate
}

// URLQuery returns a URL query string with the filter parameters.
// If parameters are present, the returned string includes a '?' prefix.
// Returns an empty string if no parameters are set.
func (f Filter) URLQuery() string {
	var params []string

	if f.ConsentID != "" {
		params = append(params, "recurringConsentId="+f.ConsentID)
	}

	if f.From != nil {
		params = append(params, "from="+f.From.String())
	}

	if f.To != nil {
		params = append(params, "to="+f.To.String())
	}

	if len(params) == 0 {
		return ""
	}

	return "?" + strings.Join(params, "&")
}
