package autopayments

import (
	"github.com/google/uuid"
	"github.com/luiky/mock-bank/internal/account"
	"github.com/luiky/mock-bank/internal/payment"
	"github.com/luiky/mock-bank/internal/timeutil"
)

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
	ClientID        string
	Creditor        []payment.Creditor `gorm:"serializer:json"`
	AdditionalInfo  *string
	DebtorAccountID *uuid.UUID `gorm:"column:account_id"`
	DebtorAccount   *account.Account
	Configuration   Configuration `gorm:"serializer:json"`

	OrgID     string
	CreatedAt timeutil.DateTime
	UpdatedAt timeutil.DateTime
}

func (Consent) TableName() string {
	return "recurring_consents"
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
			Name     string `json:"name"`
			Document struct {
				Identification string   `json:"identification"`
				Rel            Relation `json:"rel"`
			} `json:"document"`
		} `json:"contractDebtor,omitempty"`
		FirstPayment struct {
			Type                  payment.Type        `json:"type"`
			Date                  timeutil.BrazilDate `json:"date"`
			Currency              string              `json:"currency"`
			Amount                string              `json:"amount"`
			RemittanceInformation string              `json:"remittanceInformation,omitempty"`
			CreditorAccount       struct {
				ISBP        string              `json:"isbp"`
				Issuer      *string             `json:"issuer,omitempty"`
				Number      string              `json:"number"`
				AccountType payment.AccountType `json:"accountType"`
			} `json:"creditorAccount"`
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

type Relation string

const (
	CPFRelation  Relation = "CPF"
	CNPJRelation Relation = "CNPJ"
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
