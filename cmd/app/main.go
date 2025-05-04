package main

import (
	"context"
	"crypto/tls"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/luiky/mock-bank/internal/account"
	"github.com/luiky/mock-bank/internal/api"
	"github.com/luiky/mock-bank/internal/app"
	"github.com/luiky/mock-bank/internal/consent"
	"github.com/luiky/mock-bank/internal/timex"
	"github.com/luiky/mock-bank/internal/user"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

const (
	OrgID = "00000000-0000-0000-0000-000000000000"
)

var (
	env               = getEnv("ENV", "LOCAL")
	host              = getEnv("MOCKBANK_HOST", "https://mockbank.local")
	appHost           = strings.Replace(host, "https://", "https://app.", 1)
	apiHost           = strings.Replace(host, "https://", "https://api.", 1)
	apiMTLSHost       = strings.Replace(host, "https://", "https://matls-api.", 1)
	authHost          = strings.Replace(host, "https://", "https://auth.", 1)
	authMTLSHost      = strings.Replace(host, "https://", "https://matls-auth.", 1)
	directoryIssuer   = getEnv("DIRECTORY_ISSUER", "https://directory")
	directoryClientID = getEnv("DIRECTORY_ISSUER", "mockbank")
	port              = getEnv("MOCKBANK_PORT", "80")
	dbSchema          = getEnv("MOCKBANK_DB_SCHEMA", "mockbank")
	dbStringCon       = getEnv("MOCKBANK_DB_CONNECTION", "mongodb://localhost:27017/mockbank")
)

func main() {
	// Logging.
	slog.SetDefault(logger())

	// Database.
	db, err := dbConnection()
	if err != nil {
		log.Fatalf("failed to connect mongo database: %v", err)
	}

	// Storage.
	appStorage := app.NewStorage(db)
	userStorage := user.NewStorage(db)
	consentStorage := consent.NewStorage(db)
	accountStorage := account.NewStorage(db)

	// Services.
	directoryService := app.NewDirectoryService(directoryIssuer, directoryClientID, httpClient())
	appService := app.NewService(appStorage, directoryService)
	userService := user.NewService(userStorage)
	consentService := consent.NewService(consentStorage, userService)
	accountService := account.NewService(accountStorage, consentService)

	// OpenID Provider.
	op, err := openidProvider(db, userService, consentService, accountService)
	if err != nil {
		log.Fatal(err)
	}

	// Servers.
	mux := http.NewServeMux()

	op.RegisterRoutes(mux)
	app.NewServer(apiHost, appHost, appService, directoryService, userService, consentService).Register(mux)
	consent.NewServerV3(apiMTLSHost, consentService, op).Register(mux)
	account.NewServerV2(apiMTLSHost, accountService, consentService, op).Register(mux)

	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}

func dbConnection() (*mongo.Database, error) {
	ctx := context.Background()

	opts := options.Client()
	opts = opts.ApplyURI(dbStringCon)
	opts = opts.SetBSONOptions(&options.BSONOptions{
		UseJSONStructTags: true,
		NilMapAsEmpty:     true,
		NilSliceAsEmpty:   true,
	})
	conn, err := mongo.Connect(ctx, opts)
	if err != nil {
		return nil, err
	}

	if err := conn.Ping(ctx, readpref.Primary()); err != nil {
		return nil, err
	}

	return conn.Database(dbSchema), nil
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
	if clientID, ok := ctx.Value(api.CtxKeyClientID).(string); ok {
		r.AddAttrs(slog.String("client_id", clientID))
	}

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
