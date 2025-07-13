package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/luikyv/mock-bank/cmd/runutil"
	"github.com/luikyv/mock-bank/internal/account"
	"github.com/luikyv/mock-bank/internal/autopayment"
	"github.com/luikyv/mock-bank/internal/client"
	"github.com/luikyv/mock-bank/internal/page"
	"github.com/luikyv/mock-bank/internal/payment"
	"github.com/luikyv/mock-bank/internal/schedule"
	"github.com/luikyv/mock-bank/internal/timeutil"
	"github.com/luikyv/mock-bank/internal/user"
	"github.com/luikyv/mock-bank/internal/webhook"
)

var (
	Env          = runutil.EnvValue("ENV", runutil.LocalEnvironment)
	OrgID        = runutil.EnvValue("ORG_ID", "00000000-0000-0000-0000-000000000000")
	DBSecretName = runutil.EnvValue("DB_SECRET_NAME", "mockbank/db-credentials")
	// TransportCertSSMParamName and TransportKeySSMParamName are the parameters used for mutual TLS connection with the webhook client.
	TransportCertSSMParamName = runutil.EnvValue("TRANSPORT_CERT_SSM_PARAM", "/mockbank/transport-cert")
	TransportKeySSMParamName  = runutil.EnvValue("TRANSPORT_KEY_SSM_PARAM", "/mockbank/transport-key")
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	slog.SetDefault(logger())
	slog.Info("setting up mock bank scheduler", "env", Env)
	awsConfig, err := runutil.AWSConfig(ctx, Env)
	if err != nil {
		slog.Error("failed to load aws config", "error", err)
		os.Exit(1)
	}

	// Database.
	slog.Info("creating secrets manager client")
	secretsClient := secretsmanager.NewFromConfig(*awsConfig)
	slog.Info("secrets manager client created")
	db, err := runutil.DB(ctx, secretsClient, DBSecretName)
	if err != nil {
		slog.Error("failed connecting to database", "error", err)
		os.Exit(1)
	}

	// Keys.
	slog.Info("creating ssm client")
	ssmClient := ssm.NewFromConfig(*awsConfig)
	slog.Info("ssm client created")

	transportTLSCert, err := runutil.TLSCertFromSSM(ctx, ssmClient, TransportCertSSMParamName, TransportKeySSMParamName)
	if err != nil {
		slog.Error("could not load transport TLS certificate", "error", err)
		os.Exit(1)
	}

	// Services.
	clientService := client.NewService(db)
	scheduleService := schedule.NewService(db)
	webhookService := webhook.NewService(clientService, runutil.MTLSHTTPClient(transportTLSCert, Env))
	userService := user.NewService(db, OrgID)
	accountService := account.NewService(db, OrgID)
	paymentService := payment.NewService(db, userService, accountService, webhookService, scheduleService)
	autoPaymentService := autopayment.NewService(db, userService, accountService, webhookService, scheduleService)

	if Env == runutil.LocalEnvironment {
		ticker := time.NewTicker(time.Second * 10)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := pollSchedules(ctx, scheduleService, paymentService, autoPaymentService); err != nil {
					slog.ErrorContext(ctx, "error polling schedules", "error", err)
				}
			}
		}
	}

	lambda.Start(func(ctx context.Context) error {
		return pollSchedules(ctx, scheduleService, paymentService, autoPaymentService)
	})
}

func logger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
		// Make sure time is logged in UTC.
		ReplaceAttr: func(groups []string, attr slog.Attr) slog.Attr {
			if attr.Key == slog.TimeKey {
				now := timeutil.DateTimeNow()
				return slog.Attr{Key: slog.TimeKey, Value: slog.StringValue(now.String())}
			}
			return attr
		},
	}))
}

func pollSchedules(
	ctx context.Context,
	scheduleService schedule.Service,
	paymentService payment.Service,
	autoPaymentService autopayment.Service,
) error {
	slog.InfoContext(ctx, "polling schedules")
	pageSize := int32(100)
	schedules, err := scheduleService.Schedules(ctx, page.NewPagination(nil, &pageSize))
	if err != nil {
		return fmt.Errorf("failed to fetch schedules: %w", err)
	}
	slog.InfoContext(ctx, "schedules fetched", "count", len(schedules.Records), "total", schedules.TotalRecords)

	for _, s := range schedules.Records {
		slog.InfoContext(ctx, "processing schedule", "id", s.ID, "task_type", s.TaskType)
		var err error
		switch s.TaskType {
		case schedule.TaskTypePaymentConsent:
			_, err = paymentService.Consent(ctx, s.ID.String(), s.OrgID)
		case schedule.TaskTypePayment:
			_, err = paymentService.Payment(ctx, s.ID.String(), s.OrgID)
		case schedule.TaskTypeAutoPaymentConsent:
			_, err = autoPaymentService.Consent(ctx, s.ID.String(), s.OrgID)
		case schedule.TaskTypeAutoPayment:
			_, err = autoPaymentService.Payment(ctx, s.ID.String(), s.OrgID)
		}
		if err != nil {
			slog.ErrorContext(ctx, "error processing schedule", "error", err)
		}
		scheduleService.Unschedule(ctx, s.ID.String(), s.OrgID)
	}
	return nil
}
