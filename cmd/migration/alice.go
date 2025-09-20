package main

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/luikyv/mock-bank/cmd/cmdutil"
	"github.com/luikyv/mock-bank/internal/account"
	"github.com/luikyv/mock-bank/internal/creditop"
	"github.com/luikyv/mock-bank/internal/creditportability"
	"github.com/luikyv/mock-bank/internal/resource"
	"github.com/luikyv/mock-bank/internal/timeutil"
	"github.com/luikyv/mock-bank/internal/user"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// nolint:cyclop
func seedAlice(ctx context.Context, db *gorm.DB) error {
	testUser := &user.User{
		ID:        uuid.MustParse("ff8cd4db-a1c8-4966-a9ca-26ab0b19c6d1"),
		Username:  "alice@email.com",
		Name:      "Ms Alice",
		CPF:       "76109277673",
		CNPJ:      pointerOf("50685362006773"),
		CrossOrg:  true,
		UpdatedAt: timeutil.DateTimeNow(),
		OrgID:     OrgID,
	}
	if err := db.WithContext(ctx).Omit("CreatedAt").Save(testUser).Error; err != nil {
		return fmt.Errorf("failed to create test user: %w", err)
	}

	testUserCNPJ := &user.User{
		ID:        uuid.MustParse("93545348-e501-4764-a0c5-f5854cab782a"),
		Username:  "98380199000125@email.com",
		Name:      "98380199000125",
		CPF:       "98380199000",
		CNPJ:      pointerOf("98380199000125"),
		CrossOrg:  false,
		UpdatedAt: timeutil.DateTimeNow(),
		OrgID:     OrgID,
	}
	if err := db.WithContext(ctx).Omit("CreatedAt").Save(testUserCNPJ).Error; err != nil {
		return fmt.Errorf("failed to create test user: %w", err)
	}

	if err := db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "user_id"}, {Name: "business_user_id"}},
			DoNothing: true,
		}).
		Create(&user.UserBusiness{
			UserID:         testUser.ID,
			BusinessUserID: testUserCNPJ.ID,
			OrgID:          OrgID,
		}).Error; err != nil {
		return err
	}

	testAccount := &account.Account{
		ID:                          uuid.MustParse("291e5a29-49ed-401f-a583-193caa7aceee"),
		OwnerID:                     testUser.ID,
		Number:                      "94088392",
		Currency:                    "BRL",
		BranchCode:                  cmdutil.PointerOf("6272"),
		CheckDigit:                  "4",
		CompeCode:                   "123",
		BrandName:                   "Mock Bank",
		CompanyCNPJ:                 "12345678900000",
		Type:                        account.TypeCheckingAccount,
		SubType:                     account.SubTypeIndividual,
		AvailableAmount:             "100000000.04",
		BlockedAmount:               "12345.01",
		AutomaticallyInvestedAmount: "15000.00",
		OverdraftLimitContracted:    "99.99",
		OverdraftLimitUsed:          "10000.99",
		OverdraftLimitUnarranged:    "99.99",
		CrossOrg:                    true,
		OrgID:                       OrgID,
		UpdatedAt:                   timeutil.DateTimeNow(),
	}
	if err := db.WithContext(ctx).Omit("CreatedAt").Save(testAccount).Error; err != nil {
		return fmt.Errorf("failed to create test account: %w", err)
	}

	// Daily transactions.
	for i, transactionID := range []string{
		"a1e4d8fc-b3be-4b9d-927a-7d9d74e38875",
		"f5e9a9be-1b84-4e3d-8df9-9a74e476d3c9",
		"e4d19125-d9d0-4c9b-a157-7c348fe4e3a9",
		"94722695-e847-4f27-93a0-2145ef7bfa16",
		"c88c839b-d1a6-47b8-aee7-7cc3ff3562fc",
		"fc6cc1b1-0042-4f06-8ad9-1e2fa7fcbaf1",
		"ab55bb0d-82c1-4e65-875e-d318d65c4e13",
		"3f3031dc-cbfd-4e14-943f-d4c71a9e4bb6",
		"65812e1e-147b-4e5a-842e-0ae82c252c7e",
		"a5beea62-7c26-4d98-bd6c-78192ef016f6",
		"fa80e8f4-4433-4f3c-bcc3-738622a7dfd2",
		"6635e788-3d36-4d88-a22d-c36484b5c74a",
		"09c38885-c7a4-490e-a6e3-7900833f8cb6",
		"26ed33e7-e7a6-4438-8c32-3475e89361d2",
		"65f44ff8-cfc2-4c61-bf8a-c1eb9250cfb2",
		"b03c9c76-b198-4f3d-9220-5ff36cd6172d",
		"d09f1c45-8994-4ad2-bc6b-f1875cb8a238",
		"8ac5171f-1fd3-43a4-8c7b-2c6179f10555",
		"ddc27349-6f4e-4980-93bb-7bc6218fe252",
		"b22993ef-31c3-46c4-b12c-dae1451d9ed5",
		"a56a90ee-00cb-4700-837f-b5f2939ee713",
		"b23d2479-10f0-4b11-b408-8998709e37a3",
		"58e13a10-39fd-4c6c-b0e3-813cb7bc18f7",
		"14c8d474-0353-46b8-b630-1c5482e186e2",
		"fe318314-bc3a-42c4-b99a-dbb17d44f369",
		"f0e8f1ab-30f6-47f6-9240-8a8124e6a5f7",
		"55b6b409-e56d-4080-9673-8c49aeb7097e",
		"d1cd29de-0c13-47d7-b14d-1b9b1ff55da3",
		"3b3d0378-b49c-4630-8c9f-2a0e4fdef9e3",
		"d8703fbd-c57d-4fae-b0ae-2556b54a3877",
		"33f22e63-e12c-4f17-9184-c7e09be9d180",
		"848ec1f4-7f55-4d3b-bfe2-f34c6aef66aa",
		"761b9f98-dce3-41a3-bd34-27df0305fc2f",
		"85ed5cb8-71b1-4e7c-b003-36c61f00b91c",
		"ed7a0fe2-f1d4-4de3-a6fc-6796a6efbe7d",
		"35a3b9df-b1e5-40b7-95c0-ccefa93b8e07",
		"b77e80c5-2f91-4062-9617-6f7a9bc64723",
		"e27383a4-b2a1-4176-9dd2-5e57ef4372ce",
		"874d8a4f-5c20-4ed2-b538-58736f20bfb1",
		"4d9fc4c4-8a3f-4ee1-a5d0-5c46b229c7d6",
		"5ce6d545-d8d5-4f64-bec1-bfcb56aeb206",
		"9c6b5a35-1b2f-4092-8f32-32e2563b11f9",
		"15a1b15b-22ff-4c31-94cc-c68b8cb53502",
		"8de6db23-3b29-4cfa-9979-cb79f1c08925",
		"823aaaf2-5120-406b-8cd1-b136896e4ea0",
		"a7993773-9d1d-4f91-a1ee-33428f42d2f5",
		"b57c48c5-0e2b-4ec1-bb34-e01e27b2731c",
		"927733cf-3e3e-42a0-8120-bc96eb580899",
		"9fa8a8a6-d2ad-4f26-baaa-bf90e5585a6e",
		"c79cfb2a-c4bc-4be1-bd0e-6de5e1ed3b4f",
		"30240312-802b-426a-b946-8b8a8b12b1f6",
		"87cb267c-9f3a-4600-9127-d56c78c2695a",
	} {
		testTransaction := &account.Transaction{
			ID:               uuid.MustParse(transactionID),
			AccountID:        testAccount.ID,
			DateTime:         timeutil.DateTimeNow().AddDate(0, 0, -i),
			Status:           account.TransactionStatusCompleted,
			MovementType:     account.MovementTypeCredit,
			Name:             "PIX",
			Type:             account.TransactionTypePix,
			Amount:           "771.52",
			Currency:         "BRL",
			PartieBranchCode: cmdutil.PointerOf("6272"),
			PartieCheckDigit: cmdutil.PointerOf("4"),
			PartieCNPJCPF:    cmdutil.PointerOf("87517400444"),
			PartieCompeCode:  cmdutil.PointerOf("123"),
			PartieNumber:     cmdutil.PointerOf("94088392"),
			PartiePersonType: cmdutil.PointerOf(account.PersonTypeIndividual),
			OrgID:            OrgID,
			CrossOrg:         true,
			UpdatedAt:        timeutil.DateTimeNow(),
		}
		if err := db.WithContext(ctx).Omit("CreatedAt").Save(testTransaction).Error; err != nil {
			return fmt.Errorf("failed to create test transaction: %w", err)
		}
	}

	// Monthly transactions.
	for i, transactionID := range []string{
		"b8f2c1a3-7e4d-4a9f-8c2b-1d5e6f7a8b9c",
		"c9d3e2f1-8a5b-4c6d-9e1f-2a3b4c5d6e7f",
		"d4e5f6a7-9b2c-4d3e-8f1a-3b4c5d6e7f8a",
		"e5f6a7b8-0c3d-4e5f-9a2b-4c5d6e7f8a9b",
		"f6a7b8c9-1d4e-4f5a-0b2c-5d6e7f8a9b0c",
		"a7b8c9d0-2e5f-4a6b-1c3d-6e7f8a9b0c1d",
		"b8c9d0e1-3f6a-4b7c-2d4e-7f8a9b0c1d2e",
		"c9d0e1f2-4a7b-4c8d-3e5f-8a9b0c1d2e3f",
		"d0e1f2a3-5b8c-4d9e-4f6a-9b0c1d2e3f4a",
		"e1f2a3b4-6c9d-4e0f-5a7b-0c1d2e3f4a5b",
	} {
		testTransaction := &account.Transaction{
			ID:               uuid.MustParse(transactionID),
			AccountID:        testAccount.ID,
			DateTime:         timeutil.DateTimeNow().AddDate(0, -i, 0),
			Status:           account.TransactionStatusCompleted,
			MovementType:     account.MovementTypeCredit,
			Name:             "PIX",
			Type:             account.TransactionTypePix,
			Amount:           "771.52",
			Currency:         "BRL",
			PartieBranchCode: cmdutil.PointerOf("6272"),
			PartieCheckDigit: cmdutil.PointerOf("4"),
			PartieCNPJCPF:    cmdutil.PointerOf("87517400444"),
			PartieCompeCode:  cmdutil.PointerOf("123"),
			PartieNumber:     cmdutil.PointerOf("94088392"),
			PartiePersonType: cmdutil.PointerOf(account.PersonTypeIndividual),
			OrgID:            OrgID,
			CrossOrg:         true,
			UpdatedAt:        timeutil.DateTimeNow(),
		}
		if err := db.WithContext(ctx).Omit("CreatedAt").Save(testTransaction).Error; err != nil {
			return fmt.Errorf("failed to create test transaction: %w", err)
		}
	}

	testAccount2 := &account.Account{
		ID:                          uuid.MustParse("9e207cd7-a881-48e0-9755-0e6bda6cb181"),
		OwnerID:                     testUser.ID,
		Number:                      "11188222",
		Currency:                    "BRL",
		BranchCode:                  cmdutil.PointerOf("6272"),
		CheckDigit:                  "4",
		CompeCode:                   "123",
		BrandName:                   "Mock Bank",
		CompanyCNPJ:                 "12345678900000",
		Type:                        account.TypeSavingsAccount,
		SubType:                     account.SubTypeIndividual,
		AvailableAmount:             "100000000.04",
		BlockedAmount:               "12345.01",
		AutomaticallyInvestedAmount: "15000.00",
		OverdraftLimitContracted:    "99.99",
		OverdraftLimitUsed:          "10000.99",
		OverdraftLimitUnarranged:    "99.99",
		CrossOrg:                    true,
		OrgID:                       OrgID,
		UpdatedAt:                   timeutil.DateTimeNow(),
	}
	if err := db.WithContext(ctx).Omit("CreatedAt").Save(testAccount2).Error; err != nil {
		return fmt.Errorf("failed to create second test account: %w", err)
	}

	testLoan := &creditop.Contract{
		ID:                                  uuid.MustParse("dadd421d-184e-4689-a085-409d1bca4193"),
		Type:                                resource.TypeLoan,
		OwnerID:                             testUser.ID,
		CompanyCNPJ:                         "12345678900000",
		Number:                              "90847453264",
		IPOCCode:                            "01181521040211011740907325668478542336597",
		ProductName:                         "Aquisição de equipamentos",
		ProductType:                         creditop.ProductTypeLoan,
		ProductSubType:                      creditop.ProductSubTypePersonalLoanWithoutConsignment,
		ProductSubTypeCategory:              cmdutil.PointerOf(creditop.ProductSubTypeCategoryPersonal),
		Date:                                timeutil.NewBrazilDate(time.Date(2022, 1, 8, 12, 0, 0, 0, time.UTC)),
		DisbursementDates:                   cmdutil.PointerOf([]timeutil.BrazilDate{timeutil.NewBrazilDate(time.Date(2022, 1, 8, 12, 0, 0, 0, time.UTC))}),
		SettlementDate:                      cmdutil.PointerOf(timeutil.NewBrazilDate(time.Date(2021, 6, 21, 12, 0, 0, 0, time.UTC))),
		Amount:                              "12070.60",
		Currency:                            cmdutil.PointerOf("BRL"),
		DueDate:                             cmdutil.PointerOf(timeutil.NewBrazilDate(time.Date(2023, 1, 8, 12, 0, 0, 0, time.UTC))),
		InstalmentPeriodicity:               creditop.PeriodicityIrregular,
		InstalmentPeriodicityAdditionalInfo: cmdutil.PointerOf("DIA"),
		NextInstalmentAmount:                cmdutil.PointerOf("100.00"),
		FirstInstalmentDueDate:              cmdutil.PointerOf(timeutil.NewBrazilDate(time.Date(2022, 1, 8, 12, 0, 0, 0, time.UTC))),
		CET:                                 "0.015000",
		AmortizationSchedule:                creditop.AmortizationSchedulePRICE,
		AmortizationScheduleAdditionalInfo:  cmdutil.PointerOf("NA"),
		CNPJConsignee:                       cmdutil.PointerOf("13832718000196"),
		InterestRates: []creditop.InterestRate{{
			TaxType:                   creditop.TaxTypeNominal,
			Type:                      creditop.InterestRateTypeSimple,
			TaxPeriodicity:            creditop.TaxPeriodicityAA,
			Calculation:               creditop.CalculationBusinessDays,
			RateIndexerType:           creditop.RateIndexerTypeFixed,
			RateIndexerSubType:        cmdutil.PointerOf(creditop.RateIndexerSubTypeFixed),
			RateIndexerAdditionalInfo: nil,
			FixedRate:                 cmdutil.PointerOf("0.015000"),
			PostFixedRate:             cmdutil.PointerOf("0.000000"),
			AdditionalInfo:            cmdutil.PointerOf("NA"),
		}},
		ContractedFees: []creditop.Fee{{
			Name:              "Taxa de administracao",
			Code:              "ADMNISTRACAO",
			ChargeType:        creditop.ChargeTypeUnique,
			ChargeCalculation: creditop.ChargeCalculationFixed,
			Amount:            cmdutil.PointerOf("200.50"),
			Rate:              cmdutil.PointerOf("0.000000"),
		}},
		FinanceCharges: []creditop.FinanceCharge{{
			Type:           creditop.FinanceChargeTypeLatePaymentFine,
			AdditionalInfo: cmdutil.PointerOf("NA"),
			Rate:           cmdutil.PointerOf("0.060000"),
		}},
		OutstandingBalance:      "14402.37",
		PaidInstalments:         cmdutil.PointerOf(3),
		DueInstalments:          730,
		PastDueInstalments:      727,
		TotalInstalments:        cmdutil.PointerOf(1),
		TotalInstalmentType:     creditop.InstalmentPeriodicityTotalDay,
		RemainingInstalments:    cmdutil.PointerOf(727),
		HasInsuranceContracted:  cmdutil.PointerOf(false),
		RemainingInstalmentType: creditop.InstalmentPeriodicityRemainingDay,
		OrgID:                   OrgID,
		CrossOrg:                true,
		UpdatedAt:               timeutil.DateTimeNow(),
	}
	if err := db.WithContext(ctx).Omit("CreatedAt").Save(testLoan).Error; err != nil {
		return fmt.Errorf("failed to create test loan: %w", err)
	}

	balloonPayment := &creditop.BalloonPayment{
		ID:         uuid.New(),
		ContractID: testLoan.ID,
		DueDate:    timeutil.NewBrazilDate(time.Date(2020, 1, 10, 12, 0, 0, 0, time.UTC)),
		Amount:     "0.0000",
		Currency:   "BRL",
		OrgID:      OrgID,
		CrossOrg:   true,
		UpdatedAt:  timeutil.DateTimeNow(),
	}
	if err := db.WithContext(ctx).Omit("CreatedAt").Save(balloonPayment).Error; err != nil {
		return fmt.Errorf("failed to add balloon payment: %w", err)
	}

	testPortabilityEligibility := &creditportability.Eligibility{
		ID:              uuid.MustParse("dadd421d-184e-4689-a085-409d1bca4196"),
		ContractID:      testLoan.ID,
		IsEligible:      true,
		Status:          pointerOf(creditportability.EligibilityStatusAvailable),
		StatusUpdatedAt: pointerOf(timeutil.DateTimeNow()),
		Channel:         pointerOf(creditportability.ChannelOFB),
		CompanyName:     pointerOf("Empresa A"),
		CompanyCNPJ:     pointerOf("12345678901234"),
		OrgID:           OrgID,
		CrossOrg:        true,
		UpdatedAt:       timeutil.DateTimeNow(),
	}
	if err := db.WithContext(ctx).Omit("CreatedAt").Save(testPortabilityEligibility).Error; err != nil {
		return fmt.Errorf("failed to create test portability eligibility: %w", err)
	}

	testLoan2 := &creditop.Contract{
		ID:                                  uuid.MustParse("dadd421d-184e-4689-a085-409d1bca4194"),
		Type:                                resource.TypeLoan,
		OwnerID:                             testUser.ID,
		CompanyCNPJ:                         "12345678900000",
		Number:                              "90847453264",
		IPOCCode:                            "01181521040211011740907325668478542336597",
		ProductName:                         "Aquisição de equipamentos",
		ProductType:                         creditop.ProductTypeLoan,
		ProductSubType:                      creditop.ProductSubTypePersonalLoanWithoutConsignment,
		ProductSubTypeCategory:              cmdutil.PointerOf(creditop.ProductSubTypeCategoryPersonal),
		Date:                                timeutil.NewBrazilDate(time.Date(2022, 1, 8, 12, 0, 0, 0, time.UTC)),
		DisbursementDates:                   cmdutil.PointerOf([]timeutil.BrazilDate{timeutil.NewBrazilDate(time.Date(2022, 1, 8, 12, 0, 0, 0, time.UTC))}),
		SettlementDate:                      cmdutil.PointerOf(timeutil.NewBrazilDate(time.Date(2021, 6, 21, 12, 0, 0, 0, time.UTC))),
		Amount:                              "12070.60",
		Currency:                            cmdutil.PointerOf("BRL"),
		DueDate:                             cmdutil.PointerOf(timeutil.NewBrazilDate(time.Date(2023, 1, 8, 12, 0, 0, 0, time.UTC))),
		InstalmentPeriodicity:               creditop.PeriodicityIrregular,
		InstalmentPeriodicityAdditionalInfo: cmdutil.PointerOf("DIA"),
		NextInstalmentAmount:                cmdutil.PointerOf("100.00"),
		FirstInstalmentDueDate:              cmdutil.PointerOf(timeutil.NewBrazilDate(time.Date(2022, 1, 8, 12, 0, 0, 0, time.UTC))),
		CET:                                 "0.015000",
		AmortizationSchedule:                creditop.AmortizationSchedulePRICE,
		AmortizationScheduleAdditionalInfo:  cmdutil.PointerOf("NA"),
		CNPJConsignee:                       cmdutil.PointerOf("13832718000196"),
		InterestRates: []creditop.InterestRate{{
			TaxType:                   creditop.TaxTypeNominal,
			Type:                      creditop.InterestRateTypeSimple,
			TaxPeriodicity:            creditop.TaxPeriodicityAA,
			Calculation:               creditop.CalculationBusinessDays,
			RateIndexerType:           creditop.RateIndexerTypeFixed,
			RateIndexerSubType:        cmdutil.PointerOf(creditop.RateIndexerSubTypeFixed),
			RateIndexerAdditionalInfo: nil,
			FixedRate:                 cmdutil.PointerOf("0.015000"),
			PostFixedRate:             cmdutil.PointerOf("0.000000"),
			AdditionalInfo:            cmdutil.PointerOf("NA"),
		}},
		ContractedFees: []creditop.Fee{{
			Name:              "Taxa de administracao",
			Code:              "ADMNISTRACAO",
			ChargeType:        creditop.ChargeTypeUnique,
			ChargeCalculation: creditop.ChargeCalculationFixed,
			Amount:            cmdutil.PointerOf("200.50"),
			Rate:              cmdutil.PointerOf("0.000000"),
		}},
		FinanceCharges: []creditop.FinanceCharge{{
			Type:           creditop.FinanceChargeTypeLatePaymentFine,
			AdditionalInfo: cmdutil.PointerOf("NA"),
			Rate:           cmdutil.PointerOf("0.060000"),
		}},
		OutstandingBalance:      "14402.37",
		PaidInstalments:         cmdutil.PointerOf(3),
		DueInstalments:          730,
		PastDueInstalments:      727,
		TotalInstalments:        cmdutil.PointerOf(1),
		TotalInstalmentType:     creditop.InstalmentPeriodicityTotalDay,
		RemainingInstalments:    cmdutil.PointerOf(727),
		HasInsuranceContracted:  cmdutil.PointerOf(false),
		RemainingInstalmentType: creditop.InstalmentPeriodicityRemainingDay,
		OrgID:                   OrgID,
		CrossOrg:                true,
		UpdatedAt:               timeutil.DateTimeNow(),
	}
	if err := db.WithContext(ctx).Omit("CreatedAt").Save(testLoan2).Error; err != nil {
		return fmt.Errorf("failed to create test loan: %w", err)
	}

	balloonPayment2 := &creditop.BalloonPayment{
		ID:         uuid.New(),
		ContractID: testLoan2.ID,
		DueDate:    timeutil.NewBrazilDate(time.Date(2020, 1, 10, 12, 0, 0, 0, time.UTC)),
		Amount:     "100.0000",
		Currency:   "BRL",
		OrgID:      OrgID,
		CrossOrg:   true,
		UpdatedAt:  timeutil.DateTimeNow(),
	}
	if err := db.WithContext(ctx).Omit("CreatedAt").Save(balloonPayment2).Error; err != nil {
		return fmt.Errorf("failed to add balloon payment: %w", err)
	}

	testPortabilityEligibility2 := &creditportability.Eligibility{
		ID:                                uuid.MustParse("dadd421d-184e-4689-a085-409d1bca4195"),
		ContractID:                        testLoan2.ID,
		IsEligible:                        false,
		IneligibilityReason:               pointerOf(creditportability.IneligibilityReasonOther),
		IneligibilityReasonAdditionalInfo: pointerOf("Motivo da inelegibilidade"),
		OrgID:                             OrgID,
		CrossOrg:                          true,
		UpdatedAt:                         timeutil.DateTimeNow(),
	}
	if err := db.WithContext(ctx).Omit("CreatedAt").Save(testPortabilityEligibility2).Error; err != nil {
		return fmt.Errorf("failed to create test portability eligibility: %w", err)
	}

	testLoan3 := &creditop.Contract{
		ID:                                  uuid.MustParse("dadd421d-184e-4689-a085-409d1bca4197"),
		Type:                                resource.TypeLoan,
		OwnerID:                             testUser.ID,
		CompanyCNPJ:                         "12345678900000",
		Number:                              "90847453264",
		IPOCCode:                            "01181521040211011740907325668478542336597",
		ProductName:                         "Aquisição de equipamentos",
		ProductType:                         creditop.ProductTypeLoan,
		ProductSubType:                      creditop.ProductSubTypePersonalLoanWithoutConsignment,
		ProductSubTypeCategory:              cmdutil.PointerOf(creditop.ProductSubTypeCategoryPersonal),
		Date:                                timeutil.NewBrazilDate(time.Date(2022, 1, 8, 12, 0, 0, 0, time.UTC)),
		DisbursementDates:                   cmdutil.PointerOf([]timeutil.BrazilDate{timeutil.NewBrazilDate(time.Date(2022, 1, 8, 12, 0, 0, 0, time.UTC))}),
		SettlementDate:                      cmdutil.PointerOf(timeutil.NewBrazilDate(time.Date(2021, 6, 21, 12, 0, 0, 0, time.UTC))),
		Amount:                              "12070.60",
		Currency:                            cmdutil.PointerOf("BRL"),
		DueDate:                             cmdutil.PointerOf(timeutil.NewBrazilDate(time.Date(2023, 1, 8, 12, 0, 0, 0, time.UTC))),
		InstalmentPeriodicity:               creditop.PeriodicityIrregular,
		InstalmentPeriodicityAdditionalInfo: cmdutil.PointerOf("DIA"),
		NextInstalmentAmount:                cmdutil.PointerOf("100.00"),
		FirstInstalmentDueDate:              cmdutil.PointerOf(timeutil.NewBrazilDate(time.Date(2022, 1, 8, 12, 0, 0, 0, time.UTC))),
		CET:                                 "0.015000",
		AmortizationSchedule:                creditop.AmortizationSchedulePRICE,
		AmortizationScheduleAdditionalInfo:  cmdutil.PointerOf("NA"),
		CNPJConsignee:                       cmdutil.PointerOf("13832718000196"),
		InterestRates: []creditop.InterestRate{{
			TaxType:                   creditop.TaxTypeNominal,
			Type:                      creditop.InterestRateTypeSimple,
			TaxPeriodicity:            creditop.TaxPeriodicityAA,
			Calculation:               creditop.CalculationBusinessDays,
			RateIndexerType:           creditop.RateIndexerTypeFixed,
			RateIndexerSubType:        cmdutil.PointerOf(creditop.RateIndexerSubTypeFixed),
			RateIndexerAdditionalInfo: nil,
			FixedRate:                 cmdutil.PointerOf("0.015000"),
			PostFixedRate:             cmdutil.PointerOf("0.000000"),
			AdditionalInfo:            cmdutil.PointerOf("NA"),
		}},
		ContractedFees: []creditop.Fee{{
			Name:              "Taxa de administracao",
			Code:              "ADMNISTRACAO",
			ChargeType:        creditop.ChargeTypeUnique,
			ChargeCalculation: creditop.ChargeCalculationFixed,
			Amount:            cmdutil.PointerOf("200.50"),
			Rate:              cmdutil.PointerOf("0.000000"),
		}},
		FinanceCharges: []creditop.FinanceCharge{{
			Type:           creditop.FinanceChargeTypeLatePaymentFine,
			AdditionalInfo: cmdutil.PointerOf("NA"),
			Rate:           cmdutil.PointerOf("0.060000"),
		}},
		OutstandingBalance:      "14402.37",
		PaidInstalments:         cmdutil.PointerOf(3),
		DueInstalments:          730,
		PastDueInstalments:      727,
		TotalInstalments:        cmdutil.PointerOf(1),
		TotalInstalmentType:     creditop.InstalmentPeriodicityTotalDay,
		RemainingInstalments:    cmdutil.PointerOf(727),
		HasInsuranceContracted:  cmdutil.PointerOf(false),
		RemainingInstalmentType: creditop.InstalmentPeriodicityRemainingDay,
		OrgID:                   OrgID,
		CrossOrg:                true,
		UpdatedAt:               timeutil.DateTimeNow(),
	}
	if err := db.WithContext(ctx).Omit("CreatedAt").Save(testLoan3).Error; err != nil {
		return fmt.Errorf("failed to create test loan: %w", err)
	}

	testPortabilityEligibility3 := &creditportability.Eligibility{
		ID:              uuid.MustParse("dadd421d-184e-4689-a085-409d1bca4198"),
		ContractID:      testLoan3.ID,
		IsEligible:      true,
		Status:          pointerOf(creditportability.EligibilityStatusInProgress),
		StatusUpdatedAt: pointerOf(timeutil.DateTimeNow()),
		Channel:         pointerOf(creditportability.ChannelOFB),
		CompanyName:     pointerOf("Empresa B"),
		CompanyCNPJ:     pointerOf("12345678901235"),
		OrgID:           OrgID,
		CrossOrg:        true,
		UpdatedAt:       timeutil.DateTimeNow(),
	}
	if err := db.WithContext(ctx).Omit("CreatedAt").Save(testPortabilityEligibility3).Error; err != nil {
		return fmt.Errorf("failed to create test portability eligibility: %w", err)
	}

	balloonPayment3 := &creditop.BalloonPayment{
		ID:         uuid.New(),
		ContractID: testLoan3.ID,
		DueDate:    timeutil.NewBrazilDate(time.Date(2020, 1, 10, 12, 0, 0, 0, time.UTC)),
		Amount:     "100.0000",
		Currency:   "BRL",
		OrgID:      OrgID,
		CrossOrg:   true,
		UpdatedAt:  timeutil.DateTimeNow(),
	}
	if err := db.WithContext(ctx).Omit("CreatedAt").Save(balloonPayment3).Error; err != nil {
		return fmt.Errorf("failed to add balloon payment: %w", err)
	}

	testLoanWarranty := &creditop.Warranty{
		ID:         uuid.MustParse("c16b9f59-32f9-444a-b9c8-0ed93edf368b"),
		ContractID: testLoan.ID,
		Currency:   "BRL",
		Type:       creditop.WarrantyTypeCreditorRightsAssignment,
		SubType:    creditop.WarrantySubTypeSharesDebentures,
		Amount:     "15000.31",
		OrgID:      OrgID,
		CrossOrg:   true,
		UpdatedAt:  timeutil.DateTimeNow(),
	}
	if err := db.WithContext(ctx).Omit("CreatedAt").Save(testLoanWarranty).Error; err != nil {
		return fmt.Errorf("failed to add loan warranty: %w", err)
	}

	testLoanReleasePayment := &creditop.ReleasePayment{
		ID:                  uuid.MustParse("abe6e9bf-d969-44d8-87c1-f74f0f8ecb0d"),
		ContractID:          testLoan.ID,
		IsOverParcelPayment: true,
		InstalmentID:        cmdutil.PointerOf("6bb40f5a-23e4-4c46-a2a4-c287ec72c0ac"),
		Date:                timeutil.NewBrazilDate(time.Date(2021, 8, 4, 12, 0, 0, 0, time.UTC)),
		Amount:              "220.5870",
		Currency:            "BRL",
		OverParcel: &creditop.PaymentOverParcel{
			Fees: []creditop.PaymentFee{{
				Name:   "Taxa de administracao",
				Code:   "ADMNISTRACAO",
				Amount: "200.50",
			}},
			Charges: []creditop.PaymentCharge{{
				Type:           creditop.PaymentChargeTypeLatePaymentFine,
				AdditionalInfo: cmdutil.PointerOf("NA"),
				Amount:         "0.99",
			}},
		},
		OrgID:     OrgID,
		CrossOrg:  true,
		UpdatedAt: timeutil.DateTimeNow(),
	}
	if err := db.WithContext(ctx).Omit("CreatedAt").Save(testLoanReleasePayment).Error; err != nil {
		return fmt.Errorf("failed to add loan release payment: %w", err)
	}

	return nil
}
