package main

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/luikyv/mock-bank/internal/account"
	"github.com/luikyv/mock-bank/internal/timeutil"
	"github.com/luikyv/mock-bank/internal/user"
	"gorm.io/gorm"
)

func seedGabrielNunes(ctx context.Context, db *gorm.DB) error {
	testUser := &user.User{
		ID:        uuid.MustParse("7823efbb-df61-4e36-92d4-d6561c94b920"),
		Username:  "gabriel.nunes@email.com",
		Name:      "Gabriel Nunes",
		CPF:       "87517400444",
		UpdatedAt: timeutil.DateTimeNow(),
		OrgID:     OrgID,
	}

	if err := db.WithContext(ctx).Omit("CreatedAt").Save(testUser).Error; err != nil {
		return fmt.Errorf("failed to create test user: %w", err)
	}

	testAccount := &account.Account{
		ID:                          uuid.MustParse("291e5a29-49ed-401f-a583-193caa7ac79d"),
		UserID:                      testUser.ID,
		Number:                      "94088393",
		Type:                        account.TypeCheckingAccount,
		SubType:                     account.SubTypeJointSimple,
		AvailableAmount:             "100000000.04",
		BlockedAmount:               "12345.01",
		AutomaticallyInvestedAmount: "15000.00",
		OverdraftLimitContracted:    "99.99",
		OverdraftLimitUsed:          "10000.99",
		OverdraftLimitUnarranged:    "99.99",
		OrgID:                       OrgID,
	}

	if err := db.WithContext(ctx).Omit("CreatedAt").Save(testAccount).Error; err != nil {
		return fmt.Errorf("failed to create test account: %w", err)
	}

	return nil
}
