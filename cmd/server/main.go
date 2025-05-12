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

	"github.com/luiky/mock-bank/internal/api"
	"github.com/luiky/mock-bank/internal/app"
	"github.com/luiky/mock-bank/internal/opf"
	"github.com/luiky/mock-bank/internal/opf/account"
	"github.com/luiky/mock-bank/internal/opf/consent"
	"github.com/luiky/mock-bank/internal/opf/user"
	"github.com/luiky/mock-bank/internal/timex"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const (
	OrgID = "00000000-0000-0000-0000-000000000000"
)

var (
	env                = getEnv("ENV", "LOCAL")
	host               = getEnv("HOST", "https://mockbank.local")
	appHost            = strings.Replace(host, "https://", "https://app.", 1)
	apiHost            = strings.Replace(host, "https://", "https://api.", 1)
	apiMTLSHost        = strings.Replace(host, "https://", "https://matls-api.", 1)
	authHost           = strings.Replace(host, "https://", "https://auth.", 1)
	authMTLSHost       = strings.Replace(host, "https://", "https://matls-auth.", 1)
	directoryIssuer    = getEnv("DIRECTORY_ISSUER", "https://directory")
	directoryClientID  = getEnv("DIRECTORY_CLIENT_ID", "mockbank")
	port               = getEnv("PORT", "80")
	dbConnectionString = getEnv("DB_STRING", "postgres://admin:pass@localhost:5432/mockbank?sslmode=disable")
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
	opf.NewServer(apiMTLSHost, consentService, accountService, op).RegisterRoutes(mux)
	app.NewServer(appHost, appService, directoryService, userService, consentService, accountService).RegisterRoutes(mux)

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
	if interactionID, ok := ctx.Value(api.CtxKeyInteractionID).(string); ok {
		r.AddAttrs(slog.String("interaction_id", interactionID))
	}

	if orgID, ok := ctx.Value(api.CtxKeyOrgID).(string); ok {
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
