package account

import (
	"time"

	"github.com/luiky/mock-bank/internal/opf/resource"
	"github.com/luiky/mock-bank/internal/timex"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"gorm.io/gorm"
)

const (
	DefaultCompeCode  string = "001"
	DefaultBranch     string = "0001"
	DefaultCheckDigit string = "1"
	DefaultCurrency   string = "BRL"
)

var (
	Scope = goidc.NewScope("accounts")
)

type Account struct {
	ID                          string `gorm:"primaryKey"`
	UserID                      string
	OrgID                       string
	Number                      string
	Type                        Type
	SubType                     SubType
	AvailableAmount             string
	BlockedAmount               string
	AutomaticallyInvestedAmount string
	OverdraftLimitContracted    string
	OverdraftLimitUsed          string
	OverdraftLimitUnarranged    string

	Transactions []*Transaction `gorm:"foreignKey:account_id"`
}

func (acc *Account) BeforeCreate(tx *gorm.DB) error {
	acc.ID = newID(90)
	return nil
}

func (acc Account) IsJoint() bool {
	return acc.SubType == SubTypeJointSimple
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

type transactionFilter struct {
	from timex.Date
	to   timex.Date
}

type ConsentAccount struct {
	ID        string `gorm:"primaryKey"`
	ConsentID string
	AccountID string `gorm:"resource_id"`
	Status    resource.Status
	Type      resource.Type

	OrgID     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (ConsentAccount) TableName() string {
	return "consent_resources"
}

func (acc *ConsentAccount) BeforeCreate(tx *gorm.DB) error {
	acc.Type = resource.TypeAccount
	return nil
}
