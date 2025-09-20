package main

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/luikyv/mock-bank/cmd/cmdutil"
	"github.com/luikyv/mock-bank/internal/account"
	"github.com/luikyv/mock-bank/internal/timeutil"
	"github.com/luikyv/mock-bank/internal/user"
	"gorm.io/gorm"
)

func seedBob(ctx context.Context, db *gorm.DB) error {
	testUser := &user.User{
		ID:        uuid.MustParse("6fcad304-2d83-4b9c-9efe-2be4ef16d16f"),
		Username:  "bob@email.com",
		Name:      "Mr Bob",
		CPF:       "87517400444",
		CrossOrg:  true,
		UpdatedAt: timeutil.DateTimeNow(),
		OrgID:     OrgID,
	}
	if err := db.WithContext(ctx).Omit("CreatedAt").Save(testUser).Error; err != nil {
		return fmt.Errorf("failed to create test user: %w", err)
	}

	testAccount := &account.Account{
		ID:                          uuid.MustParse("291e5a29-49ed-401f-a583-193caa7ac79d"),
		OwnerID:                     testUser.ID,
		Number:                      "94088393",
		Currency:                    "BRL",
		BranchCode:                  cmdutil.PointerOf("6272"),
		CheckDigit:                  "4",
		CompeCode:                   "123",
		BrandName:                   "Mock Bank",
		CompanyCNPJ:                 "12345678900000",
		Type:                        account.TypeCheckingAccount,
		SubType:                     account.SubTypeJointSimple,
		AvailableAmount:             "12000.24",
		BlockedAmount:               "2240.00",
		AutomaticallyInvestedAmount: "14500.00",
		OverdraftLimitContracted:    "0.00",
		OverdraftLimitUsed:          "1640.06",
		OverdraftLimitUnarranged:    "99.99",
		CrossOrg:                    true,
		OrgID:                       OrgID,
		UpdatedAt:                   timeutil.DateTimeNow(),
	}
	if err := db.WithContext(ctx).Omit("CreatedAt").Save(testAccount).Error; err != nil {
		return fmt.Errorf("failed to create test account: %w", err)
	}

	return nil
}
