package account

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/luiky/mock-bank/internal/api"
	"github.com/luiky/mock-bank/internal/opf/resource"
	"github.com/luiky/mock-bank/internal/timex"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"gorm.io/gorm"
)

const (
	DefaultCompeCode  string = "001"
	DefaultBranch     string = "0001"
	DefaultCheckDigit string = "1"
)

var (
	Scope = goidc.NewScope("accounts")
)

type ConsentAccount struct {
	ConsentID uuid.UUID
	AccountID string
	Status    resource.Status

	OrgID     string
	CreatedAt time.Time
	UpdatedAt time.Time

	Account *Account
}

func (ConsentAccount) TableName() string {
	return "consent_accounts"
}

type Account struct {
	ID                          string `gorm:"primaryKey"`
	UserID                      string
	Number                      string
	Type                        Type
	SubType                     SubType `gorm:"column:subtype"`
	AvailableAmount             string
	BlockedAmount               string
	AutomaticallyInvestedAmount string
	OverdraftLimitContracted    string
	OverdraftLimitUsed          string
	OverdraftLimitUnarranged    string

	OrgID     string
	CreatedAt time.Time
	UpdatedAt time.Time

	Transactions []*Transaction `gorm:"foreignKey:account_id"`
}

func (acc *Account) BeforeCreate(tx *gorm.DB) error {
	acc.ID = newID(90)
	return nil
}

type Type string

const (
	TypeCheckingAccount Type = "CONTA_DEPOSITO_A_VISTA"
	TypeSavingsAccount  Type = "CONTA_POUPANCA"
	TypePrepaidPayment  Type = "CONTA_PAGAMENTO_PRE_PAGA"
)

type SubType string

const (
	SubTypeIndividual    SubType = "INDIVIDUAL"
	SubTypeJointSimple   SubType = "CONJUNTA_SIMPLES"
	SubTypeJointSolidary SubType = "CONJUNTA_SOLIDARIA"
)

type Transaction struct {
	ID           string `gorm:"primaryKey"`
	AccountID    string
	Status       TransactionStatus
	MovementType MovementType
	Name         string
	Type         TransactionType
	Amount       string

	OrgID     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (Transaction) TableName() string {
	return "account_transactions"
}

func (t *Transaction) BeforeCreate(tx *gorm.DB) error {
	t.ID = "TX" + newID(50)
	return nil
}

type TransactionStatus string

const (
	TransactionStatusCompleted   TransactionStatus = "TRANSACAO_EFETIVADA"
	TransactionStatusFutureEntry TransactionStatus = "LANCAMENTO_FUTURO"
	TransactionStatusProcessing  TransactionStatus = "TRANSACAO_PROCESSANDO"
)

type TransactionType string

const (
	TransactionTypeTed                       TransactionType = "TED"
	TransactionTypeDoc                       TransactionType = "DOC"
	TransactionTypePix                       TransactionType = "PIX"
	TransactionTypeTransferSameInstitution   TransactionType = "TRANSFERENCIAMESMAINSTITUICAO"
	TransactionTypeBoleto                    TransactionType = "BOLETO"
	TransactionTypeAgreementCollection       TransactionType = "CONVENIOARRECADACAO"
	TransactionTypeServicePackageFee         TransactionType = "PACOTETARIFASERVICOS"
	TransactionTypeSingleServiceFee          TransactionType = "TARIFASERVICOSAVULSOS"
	TransactionTypePayroll                   TransactionType = "FOLHAPAGAMENTO"
	TransactionTypeDeposit                   TransactionType = "DEPOSITO"
	TransactionTypeWithdrawal                TransactionType = "SAQUE"
	TransactionTypeCard                      TransactionType = "CARTAO"
	TransactionTypeOverdraftInterestCharges  TransactionType = "ENCARGOSJUROSCHEQUEESPECIAL"
	TransactionTypeFinancialInvestmentIncome TransactionType = "RENDIMENTOAPLICFINANCEIRA"
	TransactionTypeSalaryPortability         TransactionType = "PORTABILIDADESALARIO"
	TransactionTypeFinancialInvestmentRescue TransactionType = "RESGATEAPLICFINANCEIRA"
	TransactionTypeCreditOperation           TransactionType = "OPERACAOCREDITO"
	TransactionTypeOthers                    TransactionType = "OUTROS"
)

type MovementType string

const (
	MovementTypeCredit MovementType = "CREDITO"
	MovementTypeDebit  MovementType = "DEBITO"
)

type TransactionFilter struct {
	from timex.Date
	to   timex.Date
}

func NewTransactionFilter(from, to *timex.Date, current bool) (TransactionFilter, error) {
	now := timex.DateNow()
	filter := TransactionFilter{
		from: now,
		to:   timex.NewDate(now.AddDate(0, 0, 1)),
	}

	if from != nil {
		if to == nil {
			return TransactionFilter{}, api.NewError("INVALID_PARAMETER", http.StatusUnprocessableEntity, "toBookingDate is required if fromBookingDate is informed")
		}
		filter.from = *from
	}

	if to != nil {
		if from == nil {
			return TransactionFilter{}, api.NewError("INVALID_PARAMETER", http.StatusUnprocessableEntity, "fromBookingDate is required if toBookingDate is informed")
		}

		filter.to = *to
	}

	if current {
		nowMinus7Days := now.AddDate(0, 0, -7)
		if filter.from.Before(nowMinus7Days) {
			return TransactionFilter{}, api.NewError("INVALID_PARAMETER", http.StatusUnprocessableEntity, "fromBookingDate too far in the past")
		}

		if filter.to.Before(nowMinus7Days) {
			return TransactionFilter{}, api.NewError("INVALID_PARAMETER", http.StatusUnprocessableEntity, "toBookingDate too far in the past")
		}
	}

	return filter, nil
}
