package payment

import (
	"time"

	"github.com/google/uuid"
	"github.com/luiky/mock-bank/internal/account"
	"github.com/luiky/mock-bank/internal/consent"
	"github.com/luiky/mock-bank/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

var (
	Scope = goidc.NewScope("payments")
)

type Consent struct {
	ID                    uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	Status                ConsentStatus
	StatusUpdatedAt       time.Time
	ExpiresAt             time.Time
	UserID                uuid.UUID
	UserCPF               string
	BusinessCNPJ          string
	ClientID              string
	CreditorType          CreditorType
	CreditorCPFCNPJ       string `gorm:"column:creditor_cpf_cnpj"`
	CreditorName          string
	CreditorAccountISBP   string
	CreditorAccountIssuer string
	CreditorAccountNumber string
	CreditorAccountType   AccountType
	PaymentType           Type
	PaymentSchedule       *Schedule `gorm:"serializer:json"`
	PaymentDate           *time.Time
	Currency              string
	Amount                string
	IBGETownCode          string
	LocalInstrument       LocalInstrument
	QRCode                string
	Proxy                 string
	DebtorAccountID       *uuid.UUID `gorm:"column:account_id"`
	DebtorAccount         *account.Account
	RejectionReasonCode   RejectionReasonCode
	RejectionReasonDetail string

	OrgID     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (Consent) TableName() string {
	return "payment_consents"
}

func (c Consent) URN() string {
	return consent.URNPrefix + c.ID.String()
}

type ConsentStatus string

const (
	ConsentStatusAwaitingAuthorization ConsentStatus = "AWAITING_AUTHORISATION"
	ConsentStatusAuthorized            ConsentStatus = "AUTHORISED"
	ConsentStatusRejected              ConsentStatus = "REJECTED"
	ConsentStatusPartiallyAccepted     ConsentStatus = "PARTIALLY_ACCEPTED"
	ConsentStatusConsumed              ConsentStatus = "CONSUMED"
)

type CreditorType string

const (
	CreditorTypeIndividual CreditorType = "PESSOA_NATURAL"
	CreditorTypeCompany    CreditorType = "PESSOA_JURIDICA"
)

type Type string

const (
	TypePIX Type = "PIX"
)

type DayOfWeek string

const (
	DayOfWeekMonday    DayOfWeek = "SEGUNDA_FEIRA"
	DayOfWeekTuesday   DayOfWeek = "TERCA_FEIRA"
	DayOfWeekWednesday DayOfWeek = "QUARTA_FEIRA"
	DayOfWeekThursday  DayOfWeek = "QUINTA_FEIRA"
	DayOfWeekFriday    DayOfWeek = "SEXTA_FEIRA"
	DayOfWeekSaturday  DayOfWeek = "SABADO"
	DayOfWeekSunday    DayOfWeek = "DOMINGO"
)

type LocalInstrument string

const (
	LocalInstrumentManul         LocalInstrument = "MANUAL"
	LocalInstrumentPIX           LocalInstrument = "DICT"
	LocalInstrumentDynamicQRCode LocalInstrument = "QRDN"
	LocalInstrumentStaticQRCode  LocalInstrument = "QRES"
	LocalInstrumentInitiator     LocalInstrument = "INIC"
)

type AccountType string

const (
	AccountTypeCurrent            AccountType = "CACC"
	AccountTypeSavings            AccountType = "SVGS"
	AccountTypeTransactingAccount AccountType = "TRAN"
)

func ConvertAccountType(accType account.Type) AccountType {
	switch accType {
	case account.TypeCheckingAccount:
		return AccountTypeCurrent
	case account.TypeSavingsAccount:
		return AccountTypeSavings
	case account.TypePrepaidPayment:
		return AccountTypeTransactingAccount
	default:
		return ""
	}
}

type Schedule struct {
	Single *struct {
		Date timeutil.Date `json:"date"`
	} `json:"single,omitempty"`
	Daily *struct {
		StartDate timeutil.Date `json:"start_date"`
		Quantity  int           `json:"quantity"`
	} `json:"daily,omitempty"`
	Weekly *struct {
		DayOfWeek DayOfWeek     `json:"day_of_week"`
		StartDate timeutil.Date `json:"start_date"`
		Quantity  int           `json:"quantity"`
	} `json:"weekly,omitempty"`
	Monthly *struct {
		DayOfMonth int           `json:"day_of_week"`
		StartDate  timeutil.Date `json:"start_date"`
		Quantity   int           `json:"quantity"`
	} `json:"monthly,omitempty"`
	Custom *struct {
		Dates          []timeutil.Date `json:"dates"`
		AdditionalInfo string          `json:"additional_info,omitempty"`
	} `json:"custom,omitempty"`
}

type RejectionReasonCode string

const (
	RejectionReasonCodeInvalidAmount               RejectionReasonCode = "VALOR_INVALIDO"
	RejectionReasonCodeNotProvided                 RejectionReasonCode = "NAO_INFORMADO"
	RejectionReasonCodeInfrastructureFailure       RejectionReasonCode = "FALHA_INFRAESTRUTURA"
	RejectionReasonCodeAuthorizationTimeout        RejectionReasonCode = "TEMPO_EXPIRADO_AUTORIZACAO"
	RejectionReasonCodeConsumptionTimeout          RejectionReasonCode = "TEMPO_EXPIRADO_CONSUMO"
	RejectionReasonCodeRejectedByUser              RejectionReasonCode = "REJEITADO_USUARIO"
	RejectionReasonCodeSourceAndTargetAccountsSame RejectionReasonCode = "CONTAS_ORIGEM_DESTINO_IGUAIS"
	RejectionReasonCodeAccountDoesNotAllowPayment  RejectionReasonCode = "CONTA_NAO_PERMITE_PAGAMENTO"
	RejectionReasonCodeInsufficientFunds           RejectionReasonCode = "SALDO_INSUFICIENTE"
	RejectionReasonCodeAmountAboveLimit            RejectionReasonCode = "VALOR_ACIMA_LIMITE"
	RejectionReasonCodeInvalidQRCode               RejectionReasonCode = "QRCODE_INVALIDO"
)

type DebtorAccount struct {
	ISBP   string
	Issuer string
	Number string
	Type   AccountType
}
