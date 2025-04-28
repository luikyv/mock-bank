package consent

import (
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/luiky/mock-bank/internal/timex"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

const (
	maxTimeAwaitingAuthorizationSecs = 3600
	idPrefix                         = "urn:mockbank:"
	defaultUserDocumentRelation      = "CPF"
)

var (
	ScopeID = goidc.NewDynamicScope("consent", func(requestedScope string) bool {
		return strings.HasPrefix(requestedScope, "consent:")
	})
	Scope = goidc.NewScope("consents")
)

type Consent struct {
	ID              string          `bson:"_id"`
	Status          Status          `bson:"status"`
	Permissions     []Permission    `bson:"permissions"`
	CreatedAt       time.Time       `bson:"created_at"`
	StatusUpdatedAt time.Time       `bson:"status_updated_at"`
	ExpiresAt       *time.Time      `bson:"expires_at"`
	UserID          string          `bson:"user_id"`
	UserCPF         string          `bson:"user_cpf"`
	BusinessCNPJ    string          `bson:"business_cnpj"`
	ClientID        string          `bson:"client_id"`
	RejectedBy      RejectedBy      `bson:"rejected_by"`
	RejectionReason RejectionReason `bson:"rejection_reason"`
	Extensions      []Extension     `bson:"extensions"`
	AccountIDs      []string        `bson:"account_ids"`
	OrgID           string          `bson:"org_id"`
}

// HasAuthExpired returns true if the status is [StatusAwaitingAuthorization] and
// the max time awaiting authorization has elapsed.
func (c Consent) HasAuthExpired() bool {
	now := timex.Now()
	return c.IsAwaitingAuthorization() &&
		now.After(c.CreatedAt.Add(time.Second*maxTimeAwaitingAuthorizationSecs))
}

// IsExpired returns true if the status is [StatusAuthorized] and the consent
// reached the expiration date.
func (c Consent) IsExpired() bool {
	if c.ExpiresAt == nil {
		return false
	}
	now := timex.Now()
	return c.Status == StatusAuthorized && now.After(*c.ExpiresAt)
}

func (c Consent) IsAuthorized() bool {
	return c.Status == StatusAuthorized
}

func (c Consent) IsAwaitingAuthorization() bool {
	return c.Status == StatusAwaitingAuthorization
}

func (c Consent) HasPermissions(permissions []Permission) bool {
	for _, p := range permissions {
		if !slices.Contains(c.Permissions, p) {
			return false
		}
	}

	return true
}

type Status string

const (
	StatusAwaitingAuthorization Status = "AWAITING_AUTHORISATION"
	StatusAuthorized            Status = "AUTHORISED"
	StatusRejected              Status = "REJECTED"
)

type Permission string

const (
	PermissionAccountsBalanceRead                                 Permission = "ACCOUNTS_BALANCES_READ"
	PermissionAccountsOverdraftLimitsRead                         Permission = "ACCOUNTS_OVERDRAFT_LIMITS_READ"
	PermissionAccountsRead                                        Permission = "ACCOUNTS_READ"
	PermissionAccountsTransactionsRead                            Permission = "ACCOUNTS_TRANSACTIONS_READ"
	PermissionBankFixedIncomesRead                                Permission = "BANK_FIXED_INCOMES_READ"
	PermissionCreditCardsAccountsBillsRead                        Permission = "CREDIT_CARDS_ACCOUNTS_BILLS_READ"
	PermissionCreditCardsAccountsBillsTransactionsRead            Permission = "CREDIT_CARDS_ACCOUNTS_BILLS_TRANSACTIONS_READ"
	PermissionCreditCardsAccountsLimitsRead                       Permission = "CREDIT_CARDS_ACCOUNTS_LIMITS_READ"
	PermissionCreditCardsAccountsRead                             Permission = "CREDIT_CARDS_ACCOUNTS_READ"
	PermissionCreditCardsAccountsTransactionsRead                 Permission = "CREDIT_CARDS_ACCOUNTS_TRANSACTIONS_READ"
	PermissionCreditFixedIncomesRead                              Permission = "CREDIT_FIXED_INCOMES_READ"
	PermissionCustomersBusinessAdittionalInfoRead                 Permission = "CUSTOMERS_BUSINESS_ADITTIONALINFO_READ"
	PermissionCustomersBusinessIdentificationsRead                Permission = "CUSTOMERS_BUSINESS_IDENTIFICATIONS_READ"
	PermissionCustomersPersonalAdittionalInfoRead                 Permission = "CUSTOMERS_PERSONAL_ADITTIONALINFO_READ"
	PermissionCustomersPersonalIdentificationsRead                Permission = "CUSTOMERS_PERSONAL_IDENTIFICATIONS_READ"
	PermissionExchangesRead                                       Permission = "EXCHANGES_READ"
	PermissionFinancingsPaymentsRead                              Permission = "FINANCINGS_PAYMENTS_READ"
	PermissionFinancingsRead                                      Permission = "FINANCINGS_READ"
	PermissionFinancingsScheduledInstalmentsRead                  Permission = "FINANCINGS_SCHEDULED_INSTALMENTS_READ"
	PermissionFinancingsWarrantiesRead                            Permission = "FINANCINGS_WARRANTIES_READ"
	PermissionFundsRead                                           Permission = "FUNDS_READ"
	PermissionInvoiceFinancingsPaymentsRead                       Permission = "INVOICE_FINANCINGS_PAYMENTS_READ"
	PermissionInvoiceFinancingsRead                               Permission = "INVOICE_FINANCINGS_READ"
	PermissionInvoiceFinancingsScheduledInstalmentsRead           Permission = "INVOICE_FINANCINGS_SCHEDULED_INSTALMENTS_READ"
	PermissionInvoiceFinancingsWarrantiesRead                     Permission = "INVOICE_FINANCINGS_WARRANTIES_READ"
	PermissionLoansPaymentsRead                                   Permission = "LOANS_PAYMENTS_READ"
	PermissionLoansRead                                           Permission = "LOANS_READ"
	PermissionLoansScheduledInstalmentsRead                       Permission = "LOANS_SCHEDULED_INSTALMENTS_READ"
	PermissionLoansWarrantiesRead                                 Permission = "LOANS_WARRANTIES_READ"
	PermissionResourcesRead                                       Permission = "RESOURCES_READ"
	PermissionTreasureTitlesRead                                  Permission = "TREASURE_TITLES_READ"
	PermissionUnarrangedAccountsOverdraftPaymentsRead             Permission = "UNARRANGED_ACCOUNTS_OVERDRAFT_PAYMENTS_READ"
	PermissionUnarrangedAccountsOverdraftRead                     Permission = "UNARRANGED_ACCOUNTS_OVERDRAFT_READ"
	PermissionUnarrangedAccountsOverdraftScheduledInstalmentsRead Permission = "UNARRANGED_ACCOUNTS_OVERDRAFT_SCHEDULED_INSTALMENTS_READ"
	PermissionUnarrangedAccountsOverdraftWarrantiesRead           Permission = "UNARRANGED_ACCOUNTS_OVERDRAFT_WARRANTIES_READ"
	PermissionVariableIncomesRead                                 Permission = "VARIABLE_INCOMES_READ"
)

type Permissions []Permission

func (p Permissions) HasAccountPermissions() bool {
	return slices.ContainsFunc(p, func(permission Permission) bool {
		return strings.HasPrefix(string(permission), "ACCOUNTS_")
	})
}

var (
	PermissionGroupPersonalRegistrationData = []Permission{
		PermissionCustomersPersonalIdentificationsRead,
		PermissionResourcesRead,
	}
	PermissionGroupPersonalAdditionalInfo Permissions = []Permission{
		PermissionCustomersPersonalAdittionalInfoRead,
		PermissionResourcesRead,
	}
	PermissionGroupBusinessRegistrationData Permissions = []Permission{
		PermissionCustomersBusinessIdentificationsRead,
		PermissionResourcesRead,
	}
	PermissionGroupBusinessAdditionalInfo Permissions = []Permission{
		PermissionCustomersBusinessAdittionalInfoRead,
		PermissionResourcesRead,
	}
	PermissionGroupBalances Permissions = []Permission{
		PermissionAccountsRead,
		PermissionAccountsBalanceRead,
		PermissionResourcesRead,
	}
	PermissionGroupLimits Permissions = []Permission{
		PermissionAccountsRead,
		PermissionAccountsOverdraftLimitsRead,
		PermissionResourcesRead,
	}
	PermissionGroupStatements Permissions = []Permission{
		PermissionAccountsRead,
		PermissionAccountsTransactionsRead,
		PermissionResourcesRead,
	}
	PermissionGroupCreditCardLimits Permissions = []Permission{
		PermissionCreditCardsAccountsRead,
		PermissionCreditCardsAccountsLimitsRead,
		PermissionResourcesRead,
	}
	PermissionGroupCreditCardTransactions Permissions = []Permission{
		PermissionCreditCardsAccountsRead,
		PermissionCreditCardsAccountsTransactionsRead,
		PermissionResourcesRead,
	}
	PermissionGroupCreditCardBills Permissions = []Permission{
		PermissionCreditCardsAccountsRead,
		PermissionCreditCardsAccountsBillsRead,
		PermissionCreditCardsAccountsBillsTransactionsRead,
		PermissionResourcesRead,
	}
	PermissionGroupContractData Permissions = []Permission{
		PermissionLoansRead,
		PermissionLoansWarrantiesRead,
		PermissionLoansScheduledInstalmentsRead,
		PermissionLoansPaymentsRead,
		PermissionFinancingsRead,
		PermissionFinancingsWarrantiesRead,
		PermissionFinancingsScheduledInstalmentsRead,
		PermissionFinancingsPaymentsRead,
		PermissionUnarrangedAccountsOverdraftRead,
		PermissionUnarrangedAccountsOverdraftWarrantiesRead,
		PermissionUnarrangedAccountsOverdraftScheduledInstalmentsRead,
		PermissionUnarrangedAccountsOverdraftPaymentsRead,
		PermissionInvoiceFinancingsRead,
		PermissionInvoiceFinancingsWarrantiesRead,
		PermissionInvoiceFinancingsScheduledInstalmentsRead,
		PermissionInvoiceFinancingsPaymentsRead,
		PermissionResourcesRead,
	}
	PermissionGroupInvestimentOperationalData Permissions = []Permission{
		PermissionBankFixedIncomesRead,
		PermissionCreditFixedIncomesRead,
		PermissionFundsRead,
		PermissionVariableIncomesRead,
		PermissionTreasureTitlesRead,
		PermissionResourcesRead,
	}
	PermissionGroupExchangeOperationalData Permissions = []Permission{
		PermissionExchangesRead,
		PermissionResourcesRead,
	}
	PermissionGroupAll = []Permission{
		PermissionAccountsBalanceRead,
		PermissionAccountsOverdraftLimitsRead,
		PermissionAccountsRead,
		PermissionAccountsTransactionsRead,
		PermissionBankFixedIncomesRead,
		PermissionCreditCardsAccountsBillsRead,
		PermissionCreditCardsAccountsBillsTransactionsRead,
		PermissionCreditCardsAccountsLimitsRead,
		PermissionCreditCardsAccountsRead,
		PermissionCreditCardsAccountsTransactionsRead,
		PermissionCreditFixedIncomesRead,
		PermissionCustomersBusinessAdittionalInfoRead,
		PermissionCustomersBusinessIdentificationsRead,
		PermissionCustomersPersonalAdittionalInfoRead,
		PermissionCustomersPersonalIdentificationsRead,
		PermissionExchangesRead,
		PermissionFinancingsPaymentsRead,
		PermissionFinancingsRead,
		PermissionFinancingsScheduledInstalmentsRead,
		PermissionFinancingsWarrantiesRead,
		PermissionFundsRead,
		PermissionInvoiceFinancingsPaymentsRead,
		PermissionInvoiceFinancingsRead,
		PermissionInvoiceFinancingsScheduledInstalmentsRead,
		PermissionInvoiceFinancingsWarrantiesRead,
		PermissionLoansPaymentsRead,
		PermissionLoansRead,
		PermissionLoansScheduledInstalmentsRead,
		PermissionLoansWarrantiesRead,
		PermissionResourcesRead,
		PermissionTreasureTitlesRead,
		PermissionUnarrangedAccountsOverdraftPaymentsRead,
		PermissionUnarrangedAccountsOverdraftRead,
		PermissionUnarrangedAccountsOverdraftScheduledInstalmentsRead,
		PermissionUnarrangedAccountsOverdraftWarrantiesRead,
		PermissionVariableIncomesRead,
	}
)

var PermissionGroups = []Permissions{
	PermissionGroupPersonalRegistrationData,
	PermissionGroupPersonalAdditionalInfo,
	PermissionGroupBusinessRegistrationData,
	PermissionGroupBusinessAdditionalInfo,
	PermissionGroupBalances,
	PermissionGroupLimits,
	PermissionGroupStatements,
	PermissionGroupCreditCardLimits,
	PermissionGroupCreditCardTransactions,
	PermissionGroupCreditCardBills,
	PermissionGroupContractData,
	PermissionGroupInvestimentOperationalData,
	PermissionGroupExchangeOperationalData,
}

type RejectedBy string

const (
	RejectedByUser  RejectedBy = "USER"
	RejectedByASPSP RejectedBy = "ASPSP"
	RejectedByTPP   RejectedBy = "TPP"
)

type RejectionReason string

const (
	RejectionReasonConsentExpired           RejectionReason = "CONSENT_EXPIRED"
	RejectionReasonCustomerManuallyRejected RejectionReason = "CUSTOMER_MANUALLY_REJECTED"
	RejectionReasonCustomerManuallyRevoked  RejectionReason = "CUSTOMER_MANUALLY_REVOKED"
	RejectionReasonConsentMaxDateReached    RejectionReason = "CONSENT_MAX_DATE_REACHED"
	RejectionReasonConsentTechnicalIssue    RejectionReason = "CONSENT_TECHNICAL_ISSUE"
	RejectionReasonInternalSecurityReason   RejectionReason = "INTERNAL_SECURITY_REASON"
)

type Extension struct {
	ID                uuid.UUID  `gorm:"column:id;default:uuid_generate_v4();primaryKey"`
	ConsentID         uuid.UUID  `gorm:"column:consent_id"`
	ExpiresAt         *time.Time `gorm:"column:expires_at"`
	PreviousExpiresAt *time.Time `gorm:"column:previous_expires_at"`
	UserCPF           string     `gorm:"column:user_cpf"`
	BusinessCNPJ      string     `gorm:"column:business_cnpj"`
	RequestedAt       time.Time  `gorm:"column:requested_at"`
	UserIPAddress     string     `gorm:"column:user_ip"`
	UserAgent         string     `gorm:"column:user_agent"`
}

func (Extension) TableName() string {
	return "consent_extensions"
}
