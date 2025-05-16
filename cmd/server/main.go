package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/luiky/mock-bank/internal/app"
	"github.com/luiky/mock-bank/internal/opf"
	"github.com/luiky/mock-bank/internal/opf/account"
	accountv2 "github.com/luiky/mock-bank/internal/opf/account/v2"
	"github.com/luiky/mock-bank/internal/opf/consent"
	consentv3 "github.com/luiky/mock-bank/internal/opf/consent/v3"
	"github.com/luiky/mock-bank/internal/opf/user"
	"github.com/luiky/mock-bank/internal/timex"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var (
	env                = getEnv("ENV", "LOCAL")
	orgID              = getEnv("ORG_ID", "00000000-0000-0000-0000-000000000000")
	host               = getEnv("HOST", "https://mockbank.local")
	appHost            = strings.Replace(host, "https://", "https://app.", 1)
	apiMTLSHost        = strings.Replace(host, "https://", "https://matls-api.", 1)
	authHost           = strings.Replace(host, "https://", "https://auth.", 1)
	authMTLSHost       = strings.Replace(host, "https://", "https://matls-auth.", 1)
	directoryIssuer    = getEnv("DIRECTORY_ISSUER", "https://directory.local")
	directoryClientID  = getEnv("DIRECTORY_CLIENT_ID", "mockbank")
	ssJWKSURL          = getEnv("SS_JWKS_URL", "https://keystore.local")
	ssIssuer           = getEnv("SS_ISSUER", "Open Banking Open Banking Brasil sandbox SSA issuer")
	port               = getEnv("PORT", "80")
	dbConnectionString = getEnv("DB_CONNECTION_STRING", "postgres://admin:pass@localhost:5432/mockbank?sslmode=disable")
)

func main() {
	// Logging.
	slog.SetDefault(logger())

	// Database.
	db, err := dbConnection()
	if err != nil {
		log.Fatalf("failed to connect mongo database: %v", err)
	}

	// Services.
	directoryService := app.NewDirectoryService(directoryIssuer, directoryClientID, httpClient())
	appService := app.NewService(db, directoryService)
	userService := user.NewService(db)
	consentService := consent.NewService(db, userService)
	accountService := account.NewService(db)

	op, err := openidProvider(db, userService, consentService, accountService)
	if err != nil {
		log.Fatal(err)
	}

	// Servers.
	mux := http.NewServeMux()

	op.RegisterRoutes(mux)
	app.NewServer(appHost, appService, directoryService, userService, consentService, accountService).RegisterRoutes(mux)
	consentv3.NewServer(apiMTLSHost, consentService, op).RegisterRoutes(mux)
	accountv2.NewServer(apiMTLSHost, accountService, consentService, op).RegisterRoutes(mux)

	if err := http.ListenAndServe(":"+port, mux); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func dbConnection() (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(dbConnectionString), &gorm.Config{
		NowFunc: timex.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	return db, nil
}

// getEnv retrieves an environment variable or returns a fallback value if not found
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func logger() *slog.Logger {
	return slog.New(&logCtxHandler{
		Handler: slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
			// Make sure time is logged in UTC.
			ReplaceAttr: func(groups []string, attr slog.Attr) slog.Attr {
				if attr.Key == slog.TimeKey {
					utcTime := timex.Now()
					return slog.Attr{Key: slog.TimeKey, Value: slog.TimeValue(utcTime)}
				}
				return attr
			},
		}),
	})
}

type logCtxHandler struct {
	slog.Handler
}

func (h *logCtxHandler) Handle(ctx context.Context, r slog.Record) error {
	if interactionID, ok := ctx.Value(opf.CtxKeyInteractionID).(string); ok {
		r.AddAttrs(slog.String("interaction_id", interactionID))
	}

	if orgID, ok := ctx.Value(opf.CtxKeyOrgID).(string); ok {
		r.AddAttrs(slog.String("org_id", orgID))
	}

	if orgID, ok := ctx.Value(app.CtxKeyOrgID).(string); ok {
		r.AddAttrs(slog.String("org_id", orgID))
	}

	return h.Handler.Handle(ctx, r)
}

func httpClient() *http.Client {
	tlsConfig := &tls.Config{}
	if env == "LOCAL" {
		tlsConfig.InsecureSkipVerify = true
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
}
