package main

import (
	"context"
	"crypto/tls"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/luiky/mock-bank/internal/account"
	"github.com/luiky/mock-bank/internal/api"
	"github.com/luiky/mock-bank/internal/auth"
	"github.com/luiky/mock-bank/internal/consent"
	"github.com/luiky/mock-bank/internal/user"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

const (
	OrgID = "00000000-0000-0000-0000-000000000000"
)

var (
	host            = getEnv("MOCKBANK_HOST", "https://mockbank.local")
	appHost         = strings.Replace(host, "https://", "https://app.", 1)
	apiHost         = strings.Replace(host, "https://", "https://api.", 1)
	apiMTLSHost     = strings.Replace(host, "https://", "https://matls-api.", 1)
	authHost        = strings.Replace(host, "https://", "https://auth.", 1)
	authMTLSHost    = strings.Replace(host, "https://", "https://matls-auth.", 1)
	directoryIssuer = getEnv("DIRECTORY_ISSUER", "https://directory")
	port            = getEnv("MOCKBANK_PORT", "80")
	dbSchema        = getEnv("MOCKBANK_DB_SCHEMA", "mockbank")
	dbStringCon     = getEnv("MOCKBANK_DB_CONNECTION", "mongodb://localhost:27017/mockbank")
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
	authStorage := auth.NewStorage(db)
	userStorage := user.NewStorage(db)
	consentStorage := consent.NewStorage(db)
	accountStorage := account.NewStorage(db)

	// Services.
	directoryService := auth.NewDirectoryService(directoryIssuer, httpClient())
	authService := auth.NewService(authStorage, directoryService)
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

	auth.NewAppServer(appHost, authService, directoryService).Register(mux)
	user.NewAppServer(apiHost, userService, authService).Register(mux)
	consent.NewAppServer(apiHost, consentService, authService).Register(mux)

	op.RegisterRoutes(mux)
	consent.NewServerV3(apiMTLSHost, consentService, op).Register(mux)
	account.NewServerV2(apiMTLSHost, accountService, consentService, op).Register(mux)

	loadMocks(userService, accountService)

	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}

func loadMocks(userService user.Service, accountService account.Service) {
	ctx := context.Background()
	userID := "11111111-1111-1111-1111-111111111111"
	err := userService.Save(ctx, user.User{
		ID:       userID,
		CPF:      "12345678901",
		OrgID:    OrgID,
		Username: "test_user",
	})
	if err != nil {
		log.Fatalf("failed to create user: %v", err)
	}

	accountID := "11111111-1111-1111-1111-111111111112"
	_ = accountService.Save(ctx, account.Account{
		ID:      accountID,
		UserID:  userID,
		Number:  "123456789",
		Type:    account.TypeCheckingAccount,
		SubType: account.SubTypeIndividual,
	})
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
					utcTime := time.Now()
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
	return h.Handler.Handle(ctx, r)
}

func httpClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
}
