package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/golang-migrate/migrate/v4"
	migratepostgres "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/mock-bank/cmd/runutil"
	"github.com/luikyv/mock-bank/internal/client"
	"github.com/luikyv/mock-bank/internal/oidc"
	"github.com/luikyv/mock-bank/internal/timeutil"
	"gorm.io/gorm"
)

var (
	Env          = runutil.EnvValue("ENV", runutil.LocalEnvironment)
	OrgID        = runutil.EnvValue("ORG_ID", "00000000-0000-0000-0000-000000000000")
	DBSecretName = runutil.EnvValue("DB_SECRET_NAME", "mockbank/db-credentials")
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	slog.Info("setting up db migration and seeding", "env", Env)
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

	// Migrations.
	// migrationsPath := "file://../../db/migrations"
	migrationsPath := "file://db/migrations"
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

	if err := seedGabrielNunes(ctx, db); err != nil {
		return fmt.Errorf("failed to seed Gabriel Nunes: %w", err)
	}

	if Env == runutil.LocalEnvironment {
		if err := createOAuthClients(ctx, db); err != nil {
			return fmt.Errorf("failed to create OAuth client: %w", err)
		}
	}

	return nil
}

func createOAuthClients(ctx context.Context, db *gorm.DB) error {
	testClientOne := &client.Client{
		ID: "client_one",
		Data: goidc.Client{
			ID: "client_one",
			ClientMeta: goidc.ClientMeta{
				Name:                 "Client One",
				RedirectURIs:         []string{"https://localhost.emobix.co.uk:8443/test/a/mockbank/callback"},
				GrantTypes:           []goidc.GrantType{"authorization_code", "client_credentials", "implicit", "refresh_token"},
				ResponseTypes:        []goidc.ResponseType{"code id_token"},
				PublicJWKSURI:        "https://keystore.local/00000000-0000-0000-0000-000000000000/11111111-1111-1111-1111-111111111111/application.jwks",
				ScopeIDs:             "openid consents consent resources accounts customers loans payments recurring-payments recurring-consent enrollment nrp-consents",
				IDTokenKeyEncAlg:     "RSA-OAEP",
				IDTokenContentEncAlg: "A256GCM",
				TokenAuthnMethod:     goidc.ClientAuthnPrivateKeyJWT,
				TokenAuthnSigAlg:     goidc.PS256,
				CustomAttributes: map[string]any{
					oidc.OrgIDKey:      OrgID,
					oidc.OriginURIsKey: []string{"https://mockbank.local"},
				},
			},
		},
		Name:       "Client One",
		OriginURIs: []string{"https://mockbank.local"},
		OrgID:      OrgID,
		UpdatedAt:  timeutil.DateTimeNow(),
	}
	if err := db.WithContext(ctx).Omit("CreatedAt").Save(testClientOne).Error; err != nil {
		return fmt.Errorf("failed to save test client one: %w", err)
	}

	testClientTwo := &client.Client{
		ID: "client_two",
		Data: goidc.Client{
			ID: "client_two",
			ClientMeta: goidc.ClientMeta{
				Name:                 "Client Two",
				RedirectURIs:         []string{"https://localhost.emobix.co.uk:8443/test/a/mockbank/callback"},
				GrantTypes:           []goidc.GrantType{"authorization_code", "client_credentials", "implicit", "refresh_token"},
				ResponseTypes:        []goidc.ResponseType{"code id_token"},
				PublicJWKSURI:        "https://keystore.local/00000000-0000-0000-0000-000000000000/22222222-2222-2222-2222-222222222222/application.jwks",
				ScopeIDs:             "openid consents consent resources accounts customers loans payments recurring-payments recurring-consent enrollment nrp-consents",
				IDTokenKeyEncAlg:     "RSA-OAEP",
				IDTokenContentEncAlg: "A256GCM",
				TokenAuthnMethod:     goidc.ClientAuthnPrivateKeyJWT,
				TokenAuthnSigAlg:     goidc.PS256,
				CustomAttributes: map[string]any{
					oidc.OrgIDKey:      OrgID,
					oidc.OriginURIsKey: []string{"https://mockbank.local"},
				},
			},
		},
		Name:       "Client Two",
		OriginURIs: []string{"https://mockbank.local"},
		OrgID:      OrgID,
		UpdatedAt:  timeutil.DateTimeNow(),
	}
	if err := db.WithContext(ctx).Omit("CreatedAt").Save(testClientTwo).Error; err != nil {
		return fmt.Errorf("failed to save test client two: %w", err)
	}

	return nil
}
