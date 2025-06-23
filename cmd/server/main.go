package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/luikyv/mock-bank/internal/api/accountv2"
	"github.com/luikyv/mock-bank/internal/api/app"
	"github.com/luikyv/mock-bank/internal/api/autopaymentv2"
	"github.com/luikyv/mock-bank/internal/api/consentv3"
	oidcapi "github.com/luikyv/mock-bank/internal/api/oidc"
	"github.com/luikyv/mock-bank/internal/api/paymentv4"
	"github.com/luikyv/mock-bank/internal/api/resourcev3"
	"github.com/luikyv/mock-bank/internal/directory"
	"github.com/luikyv/mock-bank/internal/idempotency"
	"github.com/luikyv/mock-bank/internal/session"
	"log"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/awslabs/aws-lambda-go-api-proxy/httpadapter"
	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
	"github.com/luikyv/mock-bank/internal/account"
	"github.com/luikyv/mock-bank/internal/api"
	"github.com/luikyv/mock-bank/internal/autopayment"
	"github.com/luikyv/mock-bank/internal/consent"
	"github.com/luikyv/mock-bank/internal/oidc"
	"github.com/luikyv/mock-bank/internal/payment"
	"github.com/luikyv/mock-bank/internal/resource"
	"github.com/luikyv/mock-bank/internal/timeutil"
	"github.com/luikyv/mock-bank/internal/user"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Environment string

const (
	AWSEnvironment   Environment = "AWS"
	LocalEnvironment Environment = "LOCAL"
)

func (e Environment) IsAWS() bool {
	return strings.Contains(string(e), "AWS")
}

func (e Environment) IsLocal() bool {
	return strings.Contains(string(e), "LOCAL")
}

var (
	Env                     = getEnv("ENV", LocalEnvironment)
	OrgID                   = getEnv("ORG_ID", "00000000-0000-0000-0000-000000000000")
	BaseDomain              = getEnv("BASE_DOMAIN", "mockbank.local")
	APPHost                 = "https://app." + BaseDomain
	APIMTLSHost             = "https://matls-api." + BaseDomain
	AuthHost                = "https://auth." + BaseDomain
	AuthMTLSHost            = "https://matls-auth." + BaseDomain
	DirectoryIssuer         = getEnv("DIRECTORY_ISSUER", "https://directory.local")
	DirectoryClientID       = getEnv("DIRECTORY_CLIENT_ID", "mockbank")
	KeyStoreHost            = getEnv("KEYSTORE_HOST", "https://keystore.local")
	SoftwareStatementIssuer = getEnv("SS_ISSUER", "Open Banking Brasil sandbox SSA issuer")
	Port                    = getEnv("PORT", "80")
	DBSecretName            = getEnv("DB_SECRET_NAME", "mockbank/db-credentials")
	// OPSigningKeySSMParamName is used to sign JWTs for the OpenID Provider.
	OPSigningKeySSMParamName = getEnv("OP_SIGNING_KEY_SSM_PARAM", "/mockbank/op-signing-key")
	// DirectoryClientSigningKeySSMParamName is used to sign JWTs for the directory client.
	DirectoryClientSigningKeySSMParamName = getEnv("DIRECTORY_CLIENT_SIGNING_KEY_SSM_PARAM", "/mockbank/directory-client-signing-key")
	// DirectoryClientMTLSCertSSMParamName and DirectoryClientMTLSKeySSMParamName are used for mutual TLS connection with the directory.
	DirectoryClientMTLSCertSSMParamName = getEnv("DIRECTORY_CLIENT_MTLS_CERT_SSM_PARAM", "/mockbank/directory-client-transport-cert")
	DirectoryClientMTLSKeySSMParamName  = getEnv("DIRECTORY_CLIENT_MTLS_KEY_SSM_PARAM", "/mockbank/directory-client-transport-key")
	OrgSigningKeySSMParamName           = getEnv("ORG_SIGNING_KEY_SSM_PARAM", "/mockbank/org-signing-key")
	AWSEndpoint                         = getEnv("AWS_ENDPOINT_URL", "http://localhost:4566")
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	slog.SetDefault(logger())
	slog.Info("setting up mock bank", "env", Env)
	http.DefaultClient = httpClient()
	awsConfig := awsConfig(ctx)

	// Database.
	slog.Info("creating secrets manager client")
	secretsClient := secretsmanager.NewFromConfig(*awsConfig)
	slog.Info("secrets manager client created")
	db, err := dbConnection(ctx, secretsClient)
	if err != nil {
		log.Fatalf("failed connecting to database: %v", err)
	}

	// Keys.
	slog.Info("creating ssm client")
	ssmClient := ssm.NewFromConfig(*awsConfig)
	slog.Info("ssm client created")

	opSigner, err := signerFromSSM(ctx, ssmClient, OPSigningKeySSMParamName)
	if err != nil {
		log.Fatalf("could not load signer for op: %v\n", err)
	}

	directoryClientSigner, err := signerFromSSM(ctx, ssmClient, DirectoryClientSigningKeySSMParamName)
	if err != nil {
		log.Fatalf("could not load signer for directory: %v\n", err)
	}

	directoryClientTLSCert, err := tlsCertFromSSM(ctx, ssmClient, DirectoryClientMTLSCertSSMParamName, DirectoryClientMTLSKeySSMParamName)
	if err != nil {
		log.Fatalf("could not load directory client TLS certificate: %v\n", err)
	}

	orgSigner, err := signerFromSSM(ctx, ssmClient, OrgSigningKeySSMParamName)
	if err != nil {
		log.Fatalf("could not load signer for organization: %v\n", err)
	}

	// Services.
	directoryService := directory.NewService(DirectoryIssuer, DirectoryClientID, APPHost+"/api/directory/callback", directoryClientSigner, mtlsHTTPClient(directoryClientTLSCert))
	sessionService := session.NewService(db, directoryService)
	idempotencyService := idempotency.NewService(db)
	userService := user.NewService(db)
	consentService := consent.NewService(db, userService)
	resouceService := resource.NewService(db)
	accountService := account.NewService(db)
	paymentService := payment.NewService(db, userService, accountService)
	autoPaymentService := autopayment.NewService(db, userService, accountService)

	op, err := openidProvider(db, opSigner, userService, consentService, accountService, paymentService, autoPaymentService)
	if err != nil {
		log.Fatal(err)
	}

	// Servers.
	mux := http.NewServeMux()

	oidcapi.NewServer(AuthHost, op).RegisterRoutes(mux)
	app.NewServer(APPHost, sessionService, userService, consentService, resouceService, accountService).RegisterRoutes(mux)
	consentv3.NewServer(APIMTLSHost, consentService, op).RegisterRoutes(mux)
	resourcev3.NewServer(APIMTLSHost, resouceService, consentService, op).RegisterRoutes(mux)
	accountv2.NewServer(APIMTLSHost, accountService, consentService, op).RegisterRoutes(mux)
	paymentv4.NewServer(APIMTLSHost, paymentService, idempotencyService, op, KeyStoreHost, OrgID, orgSigner).RegisterRoutes(mux)
	autopaymentv2.NewServer(APIMTLSHost, autoPaymentService, idempotencyService, op, KeyStoreHost, OrgID, orgSigner).RegisterRoutes(mux)

	handler := middleware(mux)

	slog.Info("starting mock bank")

	go func() {
		ticker := time.NewTicker(time.Second * 10)
		for {
			select {
			case <-ctx.Done():
				slog.InfoContext(ctx, "finished polling recurring payments")
				return
			case <-ticker.C:
				slog.InfoContext(ctx, "polling recurring payments")
				if _, err := autoPaymentService.Payments(ctx, OrgID, nil); err != nil {
					slog.ErrorContext(ctx, "error polling the recurring payments", "error", err)
				}
			}
		}

	}()

	if !Env.IsAWS() {
		if err := http.ListenAndServe(":"+Port, handler); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}

		return
	}

	lambdaAdapter := httpadapter.NewV2(handler)
	lambda.Start(lambdaAdapter.ProxyWithContext)
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
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		NowFunc: func() time.Time {
			return timeutil.DateTimeNow().Time
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	slog.Info("successfully connected to database")

	return db, nil
}

// getEnv retrieves an environment variable or returns a fallback value if not found.
func getEnv[T ~string](key, fallback T) T {
	if value, exists := os.LookupEnv(string(key)); exists {
		return T(value)
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
					now := timeutil.DateTimeNow()
					return slog.Attr{Key: slog.TimeKey, Value: slog.StringValue(now.String())}
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
	if correlationID, ok := ctx.Value(api.CtxKeyCorrelationID).(string); ok {
		r.AddAttrs(slog.String("correlation_id", correlationID))
	}

	if interactionID, ok := ctx.Value(api.CtxKeyInteractionID).(string); ok {
		r.AddAttrs(slog.String("interaction_id", interactionID))
	}

	return h.Handler.Handle(ctx, r)
}

func httpClient() *http.Client {
	tlsConfig := &tls.Config{}
	if Env.IsLocal() {
		tlsConfig.InsecureSkipVerify = true
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
}

func mtlsHTTPClient(cert tls.Certificate) *http.Client {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	if Env.IsLocal() {
		tlsConfig.InsecureSkipVerify = true
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
}

func openidProvider(
	db *gorm.DB,
	signer crypto.Signer,
	userService user.Service,
	consentService consent.Service,
	accountService account.Service,
	paymentService payment.Service,
	autoPaymentService autopayment.Service,
) (
	*provider.Provider,
	error,
) {
	var scopes = []goidc.Scope{
		goidc.ScopeOpenID,
		consent.ScopeID,
		consent.Scope,
		// customer.Scope,
		account.Scope,
		// creditcard.Scope,
		// ScopeLoans,
		// ScopeFinancings,
		// ScopeUnarrangedAccountsOverdraft,
		// ScopeInvoiceFinancings,
		// ScopeBankFixedIncomes,
		// ScopeCreditFixedIncomes,
		// ScopeVariableIncomes,
		// ScopeTreasureTitles,
		// ScopeFunds,
		// ScopeExchanges,
		resource.Scope,
		payment.Scope,
		autopayment.ScopeConsentID,
		autopayment.Scope,
	}

	op, err := provider.New(goidc.ProfileFAPI1, AuthHost, func(_ context.Context) (goidc.JSONWebKeySet, error) {
		return goidc.JSONWebKeySet{
			Keys: []goidc.JSONWebKey{{
				KeyID:     "signer",
				Key:       signer.Public(),
				Use:       string(goidc.KeyUsageSignature),
				Algorithm: string(goidc.PS256),
			}},
		}, nil
	})
	if err != nil {
		return nil, err
	}

	opts := []provider.Option{
		provider.WithClientStorage(oidc.NewClientManager(db)),
		provider.WithAuthnSessionStorage(oidc.NewAuthnSessionManager(db)),
		provider.WithGrantSessionStorage(oidc.NewGrantSessionManager(db)),
		provider.WithSignerFunc(func(ctx context.Context, alg goidc.SignatureAlgorithm) (kid string, s crypto.Signer, err error) {
			return "signer", signer, nil
		}),
		provider.WithScopes(scopes...),
		provider.WithTokenOptions(oidc.TokenOptionsFunc()),
		provider.WithAuthorizationCodeGrant(),
		provider.WithImplicitGrant(),
		provider.WithRefreshTokenGrant(oidc.ShouldIssueRefreshTokenFunc(), 3600),
		provider.WithClientCredentialsGrant(),
		provider.WithTokenAuthnMethods(goidc.ClientAuthnPrivateKeyJWT),
		provider.WithPrivateKeyJWTSignatureAlgs(goidc.PS256),
		provider.WithMTLS(AuthMTLSHost, oidc.ClientCert),
		provider.WithTLSCertTokenBindingRequired(),
		provider.WithPAR(oidc.HandlePARSessionFunc(), 60),
		provider.WithJAR(goidc.PS256),
		provider.WithJAREncryption(goidc.RSA_OAEP),
		provider.WithJARContentEncryptionAlgs(goidc.A256GCM),
		provider.WithJARM(goidc.PS256),
		provider.WithIssuerResponseParameter(),
		provider.WithPKCE(goidc.CodeChallengeMethodSHA256),
		provider.WithACRs(oidc.ACROpenBankingLOA2, oidc.ACROpenBankingLOA3),
		provider.WithUserInfoSignatureAlgs(goidc.PS256),
		provider.WithUserInfoEncryption(goidc.RSA_OAEP),
		provider.WithIDTokenSignatureAlgs(goidc.PS256),
		provider.WithIDTokenEncryption(goidc.RSA_OAEP),
		provider.WithHandleGrantFunc(oidc.HandleGrantFunc(op, consentService, paymentService, autoPaymentService)),
		provider.WithPolicies(oidc.Policies(AuthHost, userService, consentService, accountService, paymentService, autoPaymentService)...),
		provider.WithNotifyErrorFunc(oidc.LogError),
		provider.WithDCR(oidc.DCRFunc(oidc.DCRConfig{
			Scopes:       scopes,
			KeyStoreHost: KeyStoreHost,
			SSIssuer:     SoftwareStatementIssuer,
		}), nil),
	}
	if err := op.WithOptions(opts...); err != nil {
		return nil, err
	}

	return op, nil
}

func awsConfig(ctx context.Context) *aws.Config {

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("unable to load aws config, %v", err)
	}

	if Env.IsLocal() {
		cfg.BaseEndpoint = &AWSEndpoint
		cfg.Credentials = credentials.NewStaticCredentialsProvider("test", "test", "")
	}
	return &cfg
}

func signerFromSSM(ctx context.Context, ssmClient *ssm.Client, paramName string) (crypto.Signer, error) {
	withDecryption := true
	out, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(paramName),
		WithDecryption: &withDecryption,
	})
	if err != nil {
		return nil, fmt.Errorf("could not fetch private key from SSM: %w", err)
	}

	block, _ := pem.Decode([]byte(aws.ToString(out.Parameter.Value)))
	if block == nil || block.Type != "PRIVATE KEY" && block.Type != "RSA PRIVATE KEY" && block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("invalid PEM block")
	}

	var parsedKey any
	switch block.Type {
	case "PRIVATE KEY":
		parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		parsedKey, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		err = fmt.Errorf("unsupported key type: %s", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	signer, ok := parsedKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("key does not implement crypto.Signer")
	}

	return signer, nil
}

func tlsCertFromSSM(ctx context.Context, ssmClient *ssm.Client, certParamName, keyParamName string) (tls.Certificate, error) {
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

func middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = context.WithValue(ctx, api.CtxKeyCorrelationID, uuid.NewString())
		slog.InfoContext(ctx, "request received", "method", r.Method, "path", r.URL.Path, "url", r.URL.String())

		start := timeutil.DateTimeNow()
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic recovered", "error", rec, "stack", string(debug.Stack()))
				api.WriteError(w, r, fmt.Errorf("internal error: %v", rec))
			}
		}()
		defer func() {
			slog.InfoContext(ctx, "request completed", slog.Duration("duration", time.Since(start.Time)))
		}()

		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}
