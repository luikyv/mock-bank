package account

import (
	"context"
	"errors"
	"slices"

	"github.com/luiky/mock-bank/internal/consent"
	"github.com/luiky/mock-bank/internal/page"
)

var (
	errNotFound                         = errors.New("account not found")
	errAccountNotAllowed                = errors.New("the account was not consented")
	errJointAccountPendingAuthorization = errors.New("the account was not authorized by all users")
)

type Service struct {
	st             Storage
	consentService consent.Service
}

func NewService(st Storage, consentService consent.Service) Service {
	return Service{
		st:             st,
		consentService: consentService,
	}
}

func (s Service) Save(ctx context.Context, acc Account) error {
	return s.st.save(ctx, acc)
}

func (s Service) AccountsByUserID(ctx context.Context, id string) ([]Account, error) {
	return s.st.accountsByUserID(ctx, id)
}

func (s Service) accounts(ctx context.Context, consentID string, pag page.Pagination) (page.Page[Account], error) {
	c, err := s.consentService.Consent(ctx, consentID)
	if err != nil {
		return page.Page[Account]{}, err
	}

	accs, err := s.st.accounts(ctx, c.AccountIDs)
	if err != nil {
		return page.Page[Account]{}, err
	}

	return page.Paginate(accs, pag), nil
}

func (s Service) account(ctx context.Context, accID, consentID string) (Account, error) {
	c, err := s.consentService.Consent(ctx, consentID)
	if err != nil {
		return Account{}, err
	}

	if !slices.Contains(c.AccountIDs, accID) {
		return Account{}, errAccountNotAllowed
	}

	return s.st.account(ctx, accID)
}

func (s Service) transactions(
	ctx context.Context,
	accID, consentID string,
	pag page.Pagination,
	filter transactionFilter,
) (
	page.Page[Transaction],
	error,
) {
	c, err := s.consentService.Consent(ctx, consentID)
	if err != nil {
		return page.Page[Transaction]{}, err
	}

	if !slices.Contains(c.AccountIDs, accID) {
		return page.Page[Transaction]{}, errAccountNotAllowed
	}

	acc, err := s.st.account(ctx, accID)
	if err != nil {
		return page.Page[Transaction]{}, err
	}

	return page.Paginate(acc.Transactions, pag), nil
}
