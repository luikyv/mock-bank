package account

import (
	"github.com/luiky/mock-bank/internal/timex"
	"github.com/luikyv/go-oidc/pkg/goidc"
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
	ID             string         `bson:"_id"`
	UserID         string         `bson:"user_id"`
	Number         string         `bson:"number"`
	Type           Type           `bson:"type"`
	SubType        SubType        `bson:"subtype"`
	Balance        Balance        `bson:"balance"`
	Transactions   []Transaction  `bson:"transactions"`
	OverdraftLimit OverdraftLimit `bson:"overdraft_limit"`
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

type Balance struct {
	AvailableAmount             string
	BlockedAmount               string
	AutomaticallyInvestedAmount string
}

type Transaction struct {
	ID           string            `bson:"id"`
	Status       TransactionStatus `bson:"status"`
	MovementType MovementType      `bson:"movement_type"`
	Name         string            `bson:"name"`
	Type         TransactionType   `bson:"type"`
	Amount       string            `bson:"amount"`
	DateTime     timex.DateTime    `bson:"datetime"`
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

type OverdraftLimit struct {
	Contracted string `bson:"contracted"`
	Used       string `bson:"used"`
	Unarranged string `bson:"unarranged"`
}

type transactionFilter struct {
	from timex.Date
	to   timex.Date
}
