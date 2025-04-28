package auth

import "context"

type Service struct {
	st Storage
}

func NewService(st Storage) Service {
	return Service{
		st: st,
	}
}

func (s Service) createSession(ctx context.Context, session Session) error {
	return s.st.createSession(ctx, session)
}

func (s Service) session(ctx context.Context, id string) (Session, error) {
	session, err := s.st.session(ctx, id)
	if err != nil {
		return Session{}, err
	}

	if session.IsExpired() {
		_ = s.deleteSession(ctx, id)
		return Session{}, errNotFound
	}
	return session, nil
}

func (s Service) deleteSession(ctx context.Context, id string) error {
	return s.st.deleteSession(ctx, id)
}
