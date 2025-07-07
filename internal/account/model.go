package account

import (
	"crypto/rand"
	"errors"
	"math/big"
	"time"

	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/mock-bank/internal/resource"
	"github.com/luikyv/mock-bank/internal/timeutil"
	"gorm.io/gorm"
)

const (
	TransactionIDLength int = 80
	letterBytes             = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

var (
	Scope = goidc.NewScope("accounts")
)

type ConsentAccount struct {
	ConsentID uuid.UUID
	AccountID uuid.UUID
	OwnerID   uuid.UUID
	Status    resource.Status
	Account   *Account

	OrgID     string
	CreatedAt timeutil.DateTime
	UpdatedAt timeutil.DateTime
}

func (ConsentAccount) TableName() string {
	return "consent_accounts"
}

type Account struct {
	ID                          uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	OwnerID                     uuid.UUID
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
	CrossOrg  bool
	CreatedAt timeutil.DateTime
	UpdatedAt timeutil.DateTime
}

type Query struct {
	ID     string
	Number string
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
	ID               string `gorm:"primaryKey"`
	AccountID        uuid.UUID
	Status           TransactionStatus
	MovementType     MovementType
	Name             string
	Type             TransactionType
	Amount           string
	PartieBranchCode *string
	PartieCheckDigit *string
	PartieCNPJCPF    *string `gorm:"column:partie_cnpj_cpf"`
	PartieCompeCode  *string
	PartieNumber     *string
	PartiePersonType *PersonType

	OrgID     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (Transaction) TableName() string {
	return "account_transactions"
}

func (t *Transaction) BeforeCreate(_ *gorm.DB) error {
	t.ID = newTransactionID()
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

type PersonType string

const (
	PersonTypeIndividual PersonType = "PESSOA_NATURAL"
	PersonTypeCompany    PersonType = "PESSOA_JURIDICA"
)

type TransactionFilter struct {
	from         timeutil.BrazilDate
	to           timeutil.BrazilDate
	movementType MovementType
}

func (f TransactionFilter) WithMovementType(mt MovementType) TransactionFilter {
	f.movementType = mt
	return f
}

func NewTransactionFilter(from, to *timeutil.BrazilDate, current bool) (TransactionFilter, error) {
	brazilNow := timeutil.BrazilDateNow()
	filter := TransactionFilter{
		from: brazilNow,
		to:   brazilNow.AddDate(0, 0, 1),
	}

	if from != nil {
		if to == nil {
			return TransactionFilter{}, errors.New("to booking date is required if from booking date is informed")
		}
		filter.from = *from
	}

	if to != nil {
		if from == nil {
			return TransactionFilter{}, errors.New("from booking date is required if to booking date is informed")
		}

		filter.to = *to
	}

	if current {
		nowMinus7Days := brazilNow.AddDate(0, 0, -7)
		if filter.from.Before(nowMinus7Days) {
			return TransactionFilter{}, errors.New("from booking date too far in the past")
		}

		if filter.to.Before(nowMinus7Days) {
			return TransactionFilter{}, errors.New("to booking date too far in the past")
		}
	}

	return filter, nil
}

func newTransactionID() string {
	b := make([]byte, TransactionIDLength)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(letterBytes))))
		if err != nil {
			panic(err)
		}
		b[i] = letterBytes[n.Int64()]
	}
	return "TX" + string(b)
}
