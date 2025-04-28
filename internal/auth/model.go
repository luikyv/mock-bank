package auth

import "github.com/luiky/mock-bank/internal/timex"

const (
	cookieSessionId = "session_id"
)

type Session struct {
	ID            string                  `bson:"_id"`
	Username      string                  `bson:"username"`
	Organizations map[string]Organization `bson:"organizations"`
	CreatedAt     timex.DateTime          `bson:"created_at"`
	ExpiresAt     timex.DateTime          `bson:"expires_at"`
}

func (s Session) IsExpired() bool {
	return s.ExpiresAt.Before(timex.Now())
}

type Organization struct {
	Name string `bson:"name"`
}
