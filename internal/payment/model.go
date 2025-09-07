package payment

import (
	"time"

	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/mock-bank/internal/account"
	"github.com/luikyv/mock-bank/internal/consent"
	"github.com/luikyv/mock-bank/internal/timeutil"
)

const (
	ConsentURNPrefix   = "urn:mockbank:consent:"
	endToEndTimeFormat = "200601021504" // yyyyMMddHHmm.
)

var (
	Scope = goidc.NewScope("payments")
)

type Payment struct {
	ID                        uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	Status                    Status
	StatusUpdatedAt           timeutil.DateTime
	EndToEndID                string
	LocalInstrument           LocalInstrument
	Amount                    string
	Currency                  string
	CreditorAccountISBP       string
	CreditorAccountIssuer     *string
	CreditorAccountNumber     string
	CreditorAccountType       AccountType
	RemittanceInformation     *string
	QRCode                    *string
	Proxy                     *string
	CNPJInitiator             string
	TransactionIdentification *string
	IBGETownCode              *string
	AuthorisationFlow         *AuthorisationFlow
	ConsentID                 uuid.UUID
	EnrollmentID              *uuid.UUID
	ClientID                  string
	DebtorAccountID           *uuid.UUID `gorm:"column:account_id"`
	DebtorAccount             *account.Account
	Date                      timeutil.BrazilDate
	Rejection                 *Rejection    `gorm:"serializer:json"`
	Cancellation              *Cancellation `gorm:"serializer:json"`
	Version                   string

	OrgID     string
	CreatedAt timeutil.DateTime
	UpdatedAt timeutil.DateTime
}

func (Payment) TableName() string {
	return "payments"
}

func (p Payment) PaymentAmount() string {
	return p.Amount
}

type Status string

const (
	StatusRCVD Status = "RCVD" // Received.
	StatusCANC Status = "CANC" // Cancelled.
	StatusACCP Status = "ACCP" // Accepted Customer Profile.
	StatusACPD Status = "ACPD" // Accepted Clearing Processed.
	StatusRJCT Status = "RJCT" // Rejected.
	StatusACSC Status = "ACSC" // Accepted Settlement Completed Debitor Account.
	StatusPDNG Status = "PDNG" // Pending.
	StatusSCHD Status = "SCHD" // Scheduled.
)

type Rejection struct {
	Code   RejectionReasonCode `json:"code"`
	Detail string              `json:"detail"`
}

type RejectionReasonCode string

const (
	RejectionInsufficientBalance             RejectionReasonCode = "SALDO_INSUFICIENTE"
	RejectionExceedsLimit                    RejectionReasonCode = "VALOR_ACIMA_LIMITE"
	RejectionInvalidAmount                   RejectionReasonCode = "VALOR_INVALIDO"
	RejectionInvalidCharge                   RejectionReasonCode = "COBRANCA_INVALIDA"
	RejectionNotInformed                     RejectionReasonCode = "NAO_INFORMADO"
	RejectionPaymentConsentMismatch          RejectionReasonCode = "PAGAMENTO_DIVERGENTE_CONSENTIMENTO"
	RejectionInvalidPaymentDetail            RejectionReasonCode = "DETALHE_PAGAMENTO_INVALIDO"
	RejectionRefusedByHolder                 RejectionReasonCode = "PAGAMENTO_RECUSADO_DETENTORA"
	RejectionRefusedBySPI                    RejectionReasonCode = "PAGAMENTO_RECUSADO_SPI"
	RejectionInfrastructureFailure           RejectionReasonCode = "FALHA_INFRAESTRUTURA"
	RejectionSPIFailure                      RejectionReasonCode = "FALHA_INFRAESTRUTURA_SPI"
	RejectionDICTFailure                     RejectionReasonCode = "FALHA_INFRAESTRUTURA_DICT"
	RejectionICPFailure                      RejectionReasonCode = "FALHA_INFRAESTRUTURA_ICP"
	RejectionReceiverPSPFailure              RejectionReasonCode = "FALHA_INFRAESTRUTURA_PSP_RECEBEDOR"
	RejectionHolderInstitutionFailure        RejectionReasonCode = "FALHA_INFRAESTRUTURA_DETENTORA"
	RejectionSameOriginAndDestinationAccount RejectionReasonCode = "CONTAS_ORIGEM_DESTINO_IGUAIS"
	RejectionPaymentSchedulingFailure        RejectionReasonCode = "FALHA_AGENDAMENTO_PAGAMENTOS"
)

type Cancellation struct {
	Reason CancellationReason `json:"cancellation_reason"`
	From   TerminatedFrom     `json:"cancellation_from"`
	At     timeutil.DateTime  `json:"cancelled_at"`
	By     string             `json:"cancelled_by"`
}

type CancellationReason string

const (
	CancellationReasonPending   CancellationReason = "CANCELADO_PENDENCIA"
	CancellationReasonScheduled CancellationReason = "CANCELADO_AGENDAMENTO"
)

type TerminatedFrom string

const (
	TerminatedFromInitiator TerminatedFrom = "INICIADORA"
	TerminatedFromHolder    TerminatedFrom = "DETENTORA"
)

type Consent struct {
	ID                         uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	Status                     ConsentStatus
	StatusUpdatedAt            timeutil.DateTime
	ExpiresAt                  timeutil.DateTime
	OwnerID                    uuid.UUID
	UserIdentification         string
	UserRel                    consent.Relation
	BusinessIdentification     *string
	BusinessRel                *consent.Relation
	ClientID                   string
	CreditorType               CreditorType
	CreditorCPFCNPJ            string `gorm:"column:creditor_cpf_cnpj"`
	CreditorName               string
	CreditorAccountISBP        string
	CreditorAccountIssuer      *string
	CreditorAccountNumber      string
	CreditorAccountType        AccountType
	PaymentType                Type
	PaymentSchedule            *Schedule `gorm:"serializer:json"`
	PaymentDate                *timeutil.BrazilDate
	PaymentCurrency            string
	PaymentAmount              string
	IBGETownCode               *string
	LocalInstrument            LocalInstrument
	QRCode                     *string
	Proxy                      *string
	DebtorAccountID            *uuid.UUID `gorm:"column:account_id"`
	DebtorAccount              *account.Account
	Rejection                  *ConsentRejection `gorm:"serializer:json"`
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
	return "payment_consents"
}

func (c Consent) URN() string {
	return ConsentURN(c.ID)
}

func (c Consent) PaymentDates() []timeutil.BrazilDate {
	if c.PaymentDate != nil {
		return []timeutil.BrazilDate{*c.PaymentDate}
	}

	schedule := c.PaymentSchedule
	switch {
	case schedule.Single != nil:
		return []timeutil.BrazilDate{schedule.Single.Date}

	case schedule.Daily != nil:
		start := schedule.Daily.StartDate
		var dates []timeutil.BrazilDate
		for i := range schedule.Daily.Quantity {
			dates = append(dates, start.AddDate(0, 0, i))
		}
		return dates

	case schedule.Weekly != nil:
		start := schedule.Weekly.StartDate
		// If start date weekday is after target weekday, move to next week.
		if start.Weekday() > schedule.Weekly.DayOfWeek.Weekday() {
			start = start.AddDate(0, 0, 7)
		}
		// Adjust to the exact target weekday.
		start = start.AddDate(0, 0, int(schedule.Weekly.DayOfWeek.Weekday()-start.Weekday()))
		var dates []timeutil.BrazilDate
		for i := range schedule.Weekly.Quantity {
			dates = append(dates, start.AddDate(0, 0, i*7))
		}
		return dates

	case schedule.Monthly != nil:
		start := schedule.Monthly.StartDate
		// If start date day is after target day, move to next month.
		if start.Day() > schedule.Monthly.DayOfMonth {
			start = start.AddDate(0, 1, 0)
		}
		var dates []timeutil.BrazilDate
		for i := range schedule.Monthly.Quantity {
			dates = append(dates, start.AddDate(0, i, 0).WithDay(schedule.Monthly.DayOfMonth))
		}
		return dates

	case schedule.Custom != nil:
		return schedule.Custom.Dates
	}

	return nil
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

func (d DayOfWeek) Weekday() time.Weekday {
	switch d {
	case DayOfWeekMonday:
		return time.Monday
	case DayOfWeekTuesday:
		return time.Tuesday
	case DayOfWeekWednesday:
		return time.Wednesday
	case DayOfWeekThursday:
		return time.Thursday
	case DayOfWeekFriday:
		return time.Friday
	case DayOfWeekSaturday:
		return time.Saturday
	case DayOfWeekSunday:
		return time.Sunday
	default:
		return 0
	}
}

type LocalInstrument string

const (
	LocalInstrumentAUTO LocalInstrument = "AUTO" // Automatic.
	LocalInstrumentMANU LocalInstrument = "MANU" // Manual.
	LocalInstrumentDICT LocalInstrument = "DICT" // PIX key.
	LocalInstrumentQRDN LocalInstrument = "QRDN" // Dynamic QR code.
	LocalInstrumentQRES LocalInstrument = "QRES" // Static QR code.
	LocalInstrumentINIC LocalInstrument = "INIC" // Initiator.
)

type AccountType string

const (
	AccountTypeCACC AccountType = "CACC" // Current.
	AccountTypeSVGS AccountType = "SVGS" // Savings.
	AccountTypeTRAN AccountType = "TRAN" // Transacting account.
)

func ConvertAccountType(accType account.Type) AccountType {
	switch accType {
	case account.TypeCheckingAccount:
		return AccountTypeCACC
	case account.TypeSavingsAccount:
		return AccountTypeSVGS
	case account.TypePrepaidPayment:
		return AccountTypeTRAN
	default:
		return ""
	}
}

type Schedule struct {
	Single *struct {
		Date timeutil.BrazilDate `json:"date"`
	} `json:"single,omitempty"`
	Daily *struct {
		StartDate timeutil.BrazilDate `json:"startDate"`
		Quantity  int                 `json:"quantity"`
	} `json:"daily,omitempty"`
	Weekly *struct {
		DayOfWeek DayOfWeek           `json:"dayOfWeek"`
		StartDate timeutil.BrazilDate `json:"startDate"`
		Quantity  int                 `json:"quantity"`
	} `json:"weekly,omitempty"`
	Monthly *struct {
		DayOfMonth int                 `json:"dayOfMonth"`
		StartDate  timeutil.BrazilDate `json:"startDate"`
		Quantity   int                 `json:"quantity"`
	} `json:"monthly,omitempty"`
	Custom *struct {
		Dates          []timeutil.BrazilDate `json:"dates"`
		AdditionalInfo string                `json:"additionalInformation,omitempty"`
	} `json:"custom,omitempty"`
}

type ConsentRejection struct {
	Code   ConsentRejectionReasonCode `json:"code"`
	Detail string                     `json:"detail"`
}

type ConsentRejectionReasonCode string

const (
	ConsentRejectionInvalidAmount               ConsentRejectionReasonCode = "VALOR_INVALIDO"
	ConsentRejectionNotProvided                 ConsentRejectionReasonCode = "NAO_INFORMADO"
	ConsentRejectionInfrastructureFailure       ConsentRejectionReasonCode = "FALHA_INFRAESTRUTURA"
	ConsentRejectionAuthorizationTimeout        ConsentRejectionReasonCode = "TEMPO_EXPIRADO_AUTORIZACAO"
	ConsentRejectionConsumptionTimeout          ConsentRejectionReasonCode = "TEMPO_EXPIRADO_CONSUMO"
	ConsentRejectionRejectedByUser              ConsentRejectionReasonCode = "REJEITADO_USUARIO"
	ConsentRejectionSourceAndTargetAccountsSame ConsentRejectionReasonCode = "CONTAS_ORIGEM_DESTINO_IGUAIS"
	ConsentRejectionAccountDoesNotAllowPayment  ConsentRejectionReasonCode = "CONTA_NAO_PERMITE_PAGAMENTO"
	ConsentRejectionInsufficientFunds           ConsentRejectionReasonCode = "SALDO_INSUFICIENTE"
	ConsentRejectionAmountAboveLimit            ConsentRejectionReasonCode = "VALOR_ACIMA_LIMITE"
	ConsentRejectionInvalidQRCode               ConsentRejectionReasonCode = "QRCODE_INVALIDO"
)

type Account struct {
	ISPB   string      `json:"ispb"`
	Issuer *string     `json:"issuer,omitempty"`
	Number string      `json:"number"`
	Type   AccountType `json:"accountType"`
}

type AuthorisationFlow string

const (
	AuthorisationFlowHybridFlow AuthorisationFlow = "HYBRID_FLOW"
	AuthorisationFlowCIBAFlow   AuthorisationFlow = "CIBA_FLOW"
	AuthorisationFlowFIDOFlow   AuthorisationFlow = "FIDO_FLOW"
)

type EnrollmentOptions struct {
	EnrollmentID           uuid.UUID
	UserIdentification     string
	BusinessIdentification *string
	DebtorAccountID        *uuid.UUID
	Challenge              string
	TransactionLimit       string
	DailyLimit             string
}

type Filter struct {
	ConsentID    string
	EnrollmentID string
	Statuses     []Status
	From         *timeutil.BrazilDate
	To           *timeutil.BrazilDate
}
