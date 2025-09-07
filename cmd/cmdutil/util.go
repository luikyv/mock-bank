package cmdutil

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/luikyv/mock-bank/internal/timeutil"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Environment string

const (
	LocalEnvironment Environment = "LOCAL"
)

func AWSConfig(ctx context.Context, env Environment) (*aws.Config, error) {

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to load aws config, %w", err)
	}

	if env == LocalEnvironment {
		cfg.BaseEndpoint = aws.String("http://aws.local:4566")
		cfg.Credentials = credentials.NewStaticCredentialsProvider("test", "test", "")
	}
	return &cfg, nil
}

func DB(ctx context.Context, sm *secretsmanager.Client, secretName string) (*gorm.DB, error) {
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
		SecretId: &secretName,
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
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
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

func TLSCertFromSSM(ctx context.Context, ssmClient *ssm.Client, certParamName, keyParamName string) (tls.Certificate, error) {
	withDecryption := true

	certOut, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(certParamName),
		WithDecryption: &withDecryption,
	})
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("could not fetch cert from SSM (%s): %w", certParamName, err)
	}

	keyOut, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(keyParamName),
		WithDecryption: &withDecryption,
	})
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("could not fetch key from SSM (%s): %w", keyParamName, err)
	}

	certPEM := []byte(aws.ToString(certOut.Parameter.Value))
	keyPEM := []byte(aws.ToString(keyOut.Parameter.Value))

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("could not parse TLS certificate: %w", err)
	}

	return tlsCert, nil
}

func MTLSHTTPClient(cert tls.Certificate, env Environment) *http.Client {
	tlsConfig := &tls.Config{
		Certificates:  []tls.Certificate{cert},
		MinVersion:    tls.VersionTLS12,
		Renegotiation: tls.RenegotiateOnceAsClient,
	}
	if env == LocalEnvironment {
		tlsConfig.InsecureSkipVerify = true
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
}

// EnvValue retrieves an environment variable or returns a fallback value if not found.
func EnvValue[T ~string](key, fallback T) T {
	if value, exists := os.LookupEnv(string(key)); exists {
		return T(value)
	}
	return fallback
}

// PointerOf returns a pointer to the given value.
func PointerOf[T any](value T) *T {
	return &value
}
