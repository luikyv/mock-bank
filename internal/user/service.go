package user

import (
	"context"
	"errors"

	"github.com/luiky/mock-bank/internal/page"
)

var (
	ErrNotFound = errors.New("user not found")
)

type Service struct {
	st Storage
}

func NewService(st Storage) Service {
	return Service{
		st: st,
	}
}

func (s Service) Save(ctx context.Context, u User) error {
	return s.st.save(ctx, u)
}

func (s Service) User(ctx context.Context, id, orgID string) (User, error) {
	return s.st.user(ctx, id, orgID)
}

func (s Service) UserByCPF(ctx context.Context, cpf, orgID string) (User, error) {
	return s.st.userByCPF(ctx, cpf, orgID)
}

func (s Service) UserByUsername(ctx context.Context, username, orgID string) (User, error) {
	return s.st.userByUsername(ctx, username, orgID)
}

func (s Service) Users(ctx context.Context, orgID string, pag page.Pagination) (page.Page[User], error) {
	return s.st.users(ctx, orgID, pag)
}

func (s Service) Delete(ctx context.Context, id, orgID string) error {
	return s.st.delete(ctx, id, orgID)
}
