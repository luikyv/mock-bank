package main

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/luikyv/mock-bank/internal/account"
	"github.com/luikyv/mock-bank/internal/creditop"
	"github.com/luikyv/mock-bank/internal/resource"
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
		CrossOrg:  true,
		UpdatedAt: timeutil.DateTimeNow(),
		OrgID:     OrgID,
	}

	if err := db.WithContext(ctx).Omit("CreatedAt").Save(testUser).Error; err != nil {
		return fmt.Errorf("failed to create test user: %w", err)
	}

	testAccount := &account.Account{
		ID:                          uuid.MustParse("291e5a29-49ed-401f-a583-193caa7aceee"),
		OwnerID:                     testUser.ID,
		Number:                      "94088392",
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

	testLoan := &creditop.Contract{
		ID:                                  uuid.MustParse("dadd421d-184e-4689-a085-409d1bca4193"),
		Type:                                resource.TypeLoan,
		OwnerID:                             testUser.ID,
		Number:                              "90847453264",
		IPOCCode:                            "01181521040211011740907325668478542336597",
		ProductName:                         "Aquisição de equipamentos",
		ProductType:                         creditop.ProductTypeLoan,
		ProductSubType:                      creditop.ProductSubTypePersonalLoanWithoutConsignment,
		ProductSubTypeCategory:              pointerOf(creditop.ProductSubTypeCategoryPersonal),
		Date:                                timeutil.NewBrazilDate(time.Date(2022, 1, 8, 12, 0, 0, 0, time.UTC)),
		DisbursementDates:                   pointerOf([]timeutil.BrazilDate{timeutil.NewBrazilDate(time.Date(2022, 1, 8, 12, 0, 0, 0, time.UTC))}),
		SettlementDate:                      pointerOf(timeutil.NewBrazilDate(time.Date(2021, 6, 21, 12, 0, 0, 0, time.UTC))),
		Amount:                              "12070.60",
		Currency:                            pointerOf("BRL"),
		DueDate:                             pointerOf(timeutil.NewBrazilDate(time.Date(2023, 1, 8, 12, 0, 0, 0, time.UTC))),
		InstalmentPeriodicity:               creditop.PeriodicityIrregular,
		InstalmentPeriodicityAdditionalInfo: pointerOf("DIA"),
		NextInstalmentAmount:                pointerOf("100.00"),
		FirstInstalmentDueDate:              pointerOf(timeutil.NewBrazilDate(time.Date(2022, 1, 8, 12, 0, 0, 0, time.UTC))),
		CET:                                 "0.015000",
		AmortizationSchedule:                creditop.AmortizationSchedulePRICE,
		AmortizationScheduleAdditionalInfo:  pointerOf("NA"),
		CNPJConsignee:                       pointerOf("13832718000196"),
		InterestRates: []creditop.InterestRate{{
			TaxType:                   creditop.TaxTypeNominal,
			Type:                      creditop.InterestRateTypeSimple,
			TaxPeriodicity:            creditop.TaxPeriodicityAA,
			Calculation:               creditop.CalculationBusinessDays,
			RateIndexerType:           creditop.RateIndexerTypeFixed,
			RateIndexerSubType:        pointerOf(creditop.RateIndexerSubTypeFixed),
			RateIndexerAdditionalInfo: nil,
			FixedRate:                 pointerOf("0.015000"),
			PostFixedRate:             pointerOf("0.000000"),
			AdditionalInfo:            pointerOf("NA"),
		}},
		ContractedFees: []creditop.Fee{{
			Name:              "Taxa de administracao",
			Code:              "ADMNISTRACAO",
			ChargeType:        creditop.ChargeTypeUnique,
			ChargeCalculation: creditop.ChargeCalculationFixed,
			Amount:            pointerOf("200.50"),
			Rate:              pointerOf("0.000000"),
		}},
		FinanceCharges: []creditop.FinanceCharge{{
			Type:           creditop.FinanceChargeTypeLatePaymentFine,
			AdditionalInfo: pointerOf("NA"),
			Rate:           pointerOf("0.060000"),
		}},
		OutstandingBalance:      "14402.37",
		PaidInstalments:         pointerOf(3),
		DueInstalments:          730,
		PastDueInstalments:      727,
		TotalInstalments:        pointerOf(1),
		TotalInstalmentType:     creditop.InstalmentPeriodicityTotalDay,
		RemainingInstalments:    pointerOf(727),
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
		InstalmentID:        pointerOf("6bb40f5a-23e4-4c46-a2a4-c287ec72c0ac"),
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
				AdditionalInfo: pointerOf("NA"),
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
