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

func seedRalphBragg(ctx context.Context, db *gorm.DB) error {
	cnpj := "50685362006773"
	testUser := &user.User{
		ID:        uuid.MustParse("ff8cd4db-a1c8-4966-a9ca-26ab0b19c6d1"),
		Username:  "ralph.bragg@gmail.com",
		Name:      "Ralph Bragg",
		CPF:       "76109277673",
		CNPJ:      &cnpj,
		UpdatedAt: timeutil.DateTimeNow(),
		OrgID:     OrgID,
	}

	if err := db.WithContext(ctx).Omit("CreatedAt").Save(testUser).Error; err != nil {
		return fmt.Errorf("failed to create test user: %w", err)
	}

	testAccount := &account.Account{
		ID:                          uuid.MustParse("291e5a29-49ed-401f-a583-193caa7aceee"),
		UserID:                      testUser.ID,
		Number:                      "94088392",
		Type:                        account.TypeCheckingAccount,
		SubType:                     account.SubTypeIndividual,
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
