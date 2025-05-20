package session

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/luiky/mock-bank/internal/timeutil"
)

type Session struct {
	ID            uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	Username      string
	Organizations Organizations `gorm:"type:jsonb"`

	CreatedAt time.Time
	ExpiresAt time.Time
}

func (s Session) IsExpired() bool {
	return s.ExpiresAt.Before(timeutil.Now())
}

type Organizations map[string]struct {
	Name string `json:"name"`
}

func (o Organizations) Value() (driver.Value, error) {
	return json.Marshal(o)
}

func (o *Organizations) Scan(value any) error {
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to convert value to []byte")
	}
	return json.Unmarshal(bytes, o)
}
