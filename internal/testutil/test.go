package testutil

import (
	"testing"
	"time"

	"github.com/luikyv/mock-bank/internal/timeutil"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const (
	OrgID = "mock-org-id"
	dsn   = "host=localhost port=5432 user=admin password=pass dbname=mockbank sslmode=disable connect_timeout=5"
)

var testDB *gorm.DB

func NewDB(t testing.TB) *gorm.DB {
	t.Helper()

	if testDB == nil {
		testDB = initDB(t)
	}

	tx := testDB.Begin()
	if tx.Error != nil {
		t.Fatalf("failed to begin transaction: %v", tx.Error)
	}

	t.Cleanup(func() {
		if err := tx.Rollback().Error; err != nil {
			t.Fatalf("failed to rollback transaction: %v", err)
		}
	})

	return tx
}

func initDB(t testing.TB) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		NowFunc: func() time.Time {
			return timeutil.DateTimeNow().Time
		},
	})
	if err != nil {
		t.Fatalf("failed to connect to database: %v", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("failed to get sql.DB from gorm DB: %v", err)
	}
	if err := sqlDB.Ping(); err != nil {
		t.Fatalf("failed to ping database: %v", err)
	}

	return db
}

func PointerOf[T any](v T) *T {
	return &v
}
