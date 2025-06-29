package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/golang-migrate/migrate/v4"
	migratepostgres "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/mock-bank/internal/client"
	"github.com/luikyv/mock-bank/internal/oidc"
	"github.com/luikyv/mock-bank/internal/timeutil"
	gormpostgres "gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Environment string

const (
	LocalEnvironment Environment = "LOCAL"
)

var (
	Env          = getEnv("ENV", LocalEnvironment)
	OrgID        = getEnv("ORG_ID", "00000000-0000-0000-0000-000000000000")
	DBSecretName = getEnv("DB_SECRET_NAME", "mockbank/db-credentials")
	AWSEndpoint  = getEnv("AWS_ENDPOINT_URL", "http://localhost:4566")
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	slog.Info("setting up db migration and seeding", "env", Env)
	awsConfig := awsConfig(ctx)

	// Database.
	slog.Info("creating secrets manager client")
	secretsClient := secretsmanager.NewFromConfig(*awsConfig)
	slog.Info("secrets manager client created")
	db, err := dbConnection(ctx, secretsClient)
	if err != nil {
		slog.Error("failed connecting to database", "error", err)
		os.Exit(1)
	}

	// Migrations.
	migrationsPath := "file://db/migrations"
	if Env == LocalEnvironment {
		migrationsPath = "file://../../db/migrations"
	}
	slog.Info("running database migrations")
	if err := runMigrations(db, migrationsPath); err != nil {
		slog.Error("failed to run migrations", "error", err)
		os.Exit(1)
	}
	slog.Info("migrations completed successfully")

	// Seed database.
	slog.Info("seeding database")
	if err := seedDatabase(ctx, db); err != nil {
		slog.Error("failed to seed database", "error", err)
		os.Exit(1)
	}
	slog.Info("database seeding completed successfully")
}

func runMigrations(db *gorm.DB, migrationsPath string) error {
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	driver, err := migratepostgres.WithInstance(sqlDB, &migratepostgres.Config{})
	if err != nil {
		return fmt.Errorf("failed to create postgres driver: %w", err)
	}

	m, err := migrate.NewWithDatabaseInstance(migrationsPath, "postgres", driver)
	if err != nil {
		return fmt.Errorf("failed to create migrate instance: %w", err)
	}

	slog.Info("running migrations")
	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			slog.Info("no migrations to run")
			return nil
		}
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	slog.Info("migrations completed successfully")
	return nil
}

func seedDatabase(ctx context.Context, db *gorm.DB) error {
	if err := seedRalphBragg(ctx, db); err != nil {
		return fmt.Errorf("failed to seed Ralph Bragg: %w", err)
	}

	if Env == LocalEnvironment {
		if err := createOAuthClients(ctx, db); err != nil {
			return fmt.Errorf("failed to create OAuth client: %w", err)
		}
	}

	return nil
}

func createOAuthClients(ctx context.Context, db *gorm.DB) error {
	oidcClient := &goidc.Client{
		ID: "client_one",
		ClientMeta: goidc.ClientMeta{
			Name:                 "Client One",
			RedirectURIs:         []string{"https://localhost.emobix.co.uk:8443/test/a/mockbank/callback"},
			GrantTypes:           []goidc.GrantType{"authorization_code", "client_credentials", "implicit", "refresh_token"},
			ResponseTypes:        []goidc.ResponseType{"code id_token"},
			PublicJWKSURI:        "https://keystore.local/00000000-0000-0000-0000-000000000000/11111111-1111-1111-1111-111111111111/application.jwks",
			ScopeIDs:             "openid consents consent resources accounts payments recurring-payments recurring-consent enrollment nrp-consents",
			IDTokenKeyEncAlg:     "RSA-OAEP",
			IDTokenContentEncAlg: "A256GCM",
			TokenAuthnMethod:     goidc.ClientAuthnPrivateKeyJWT,
			TokenAuthnSigAlg:     goidc.PS256,
			CustomAttributes: map[string]any{
				oidc.OrgIDKey: OrgID,
				oidc.SoftwareOriginURIsKey: []string{
					"https://localhost.emobix.co.uk:8443/test/a/mockbank",
				},
			},
		},
	}

	clientEntity := &client.Client{
		ID:   oidcClient.ID,
		Data: *oidcClient,
		Name: oidcClient.Name,
		OriginURIs: []string{
			"https://mockbank.local",
		},
		OrgID:     OrgID,
		UpdatedAt: timeutil.DateTimeNow(),
	}

	return db.WithContext(ctx).Omit("CreatedAt").Save(clientEntity).Error
}

func getEnv[T ~string](key, fallback T) T {
	if value, exists := os.LookupEnv(string(key)); exists {
		return T(value)
	}
	return fallback
}

func awsConfig(ctx context.Context) *aws.Config {

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		slog.Error("unable to load aws config", "error", err)
		os.Exit(1)
	}

	if Env == LocalEnvironment {
		cfg.BaseEndpoint = &AWSEndpoint
		cfg.Credentials = credentials.NewStaticCredentialsProvider("test", "test", "")
	}
	return &cfg
}

func dbConnection(ctx context.Context, sm *secretsmanager.Client) (*gorm.DB, error) {
	type dbSecret struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Host     string `json:"host"`
		Port     int    `json:"port"`
		DBName   string `json:"dbname"`
		Engine   string `json:"engine"`
		SSLMode  string `json:"sslmode"`
	}

	slog.Info("retrieving database credentials from secrets manager")
	resp, err := sm.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: &DBSecretName,
	})
	slog.Info("retrieved database credentials from secrets manager")
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	var secret dbSecret
	if err := json.Unmarshal([]byte(*resp.SecretString), &secret); err != nil {
		return nil, fmt.Errorf("failed to parse secret JSON: %w", err)
	}

	if secret.SSLMode == "" {
		secret.SSLMode = "require"
	}

	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s connect_timeout=5",
		secret.Host, secret.Port, secret.Username, secret.Password, secret.DBName, secret.SSLMode)

	slog.Info("connecting to database")
	db, err := gorm.Open(gormpostgres.Open(dsn), &gorm.Config{
		NowFunc: func() time.Time {
			return timeutil.DateTimeNow().Time
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get sql.DB from gorm DB: %w", err)
	}
	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	slog.Info("successfully connected to database")

	return db, nil
}
