package account

import (
	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/mock-bank/internal/errorutil"
	"github.com/luikyv/mock-bank/internal/resource"
	"github.com/luikyv/mock-bank/internal/timeutil"
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
	BranchCode                  *string
	BrandName                   string
	CheckDigit                  string
	CompanyCNPJ                 string `gorm:"column:company_cnpj"`
	CompeCode                   string
	Type                        Type
	SubType                     SubType `gorm:"column:subtype"`
	AvailableAmount             string
	BlockedAmount               string
	AutomaticallyInvestedAmount string
	OverdraftLimitContracted    string
	OverdraftLimitUsed          string
	OverdraftLimitUnarranged    string
	Currency                    string

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
	ID               uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	AccountID        uuid.UUID
	Status           TransactionStatus
	DateTime         timeutil.DateTime
	MovementType     MovementType
	Name             string
	Type             TransactionType
	Amount           string
	Currency         string
	PartieBranchCode *string
	PartieCheckDigit *string
	PartieCNPJCPF    *string `gorm:"column:partie_cnpj_cpf"`
	PartieCompeCode  *string
	PartieNumber     *string
	PartiePersonType *PersonType

	OrgID     string
	CrossOrg  bool
	CreatedAt timeutil.DateTime
	UpdatedAt timeutil.DateTime
}

func (Transaction) TableName() string {
	return "account_transactions"
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

func NewTransactionFilter(from, to *string) (TransactionFilter, error) {
	today := timeutil.BrazilDateNow()
	filter := TransactionFilter{
		from: today.StartOfDay(),
		to:   today.EndOfDay(),
	}

	if from != nil {
		fromDate, err := timeutil.ParseBrazilDate(*from)
		if err != nil {
			return TransactionFilter{}, errorutil.Format("invalid from booking date: %w", err)
		}
		filter.from = fromDate.StartOfDay()

		if to == nil {
			return TransactionFilter{}, errorutil.New("to booking date is required if from booking date is informed")
		}
	}

	if to != nil {
		toDate, err := timeutil.ParseBrazilDate(*to)
		if err != nil {
			return TransactionFilter{}, errorutil.Format("invalid to booking date: %w", err)
		}
		filter.to = toDate.EndOfDay()

		if from == nil {
			return TransactionFilter{}, errorutil.New("from booking date is required if to booking date is informed")
		}
	}

	if filter.from.After(filter.to) {
		return TransactionFilter{}, errorutil.New("from booking date must be before to booking date")
	}

	return filter, nil
}

func NewCurrentTransactionFilter(from, to *string) (TransactionFilter, error) {
	filter, err := NewTransactionFilter(from, to)
	if err != nil {
		return TransactionFilter{}, err
	}

	today := timeutil.BrazilDateNow()
	if filter.from.Before(today.AddDate(0, 0, -7)) {
		return TransactionFilter{}, errorutil.New("from booking date too far in the past")
	}

	if filter.to.After(today.AddDate(1, 0, 0)) {
		return TransactionFilter{}, errorutil.New("to booking date too far in the future")
	}

	return filter, nil
}
