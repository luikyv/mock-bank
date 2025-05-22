package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	smithyendpoints "github.com/aws/smithy-go/endpoints"
	"github.com/luiky/mock-bank/internal/account"
	"github.com/luiky/mock-bank/internal/api"
	"github.com/luiky/mock-bank/internal/api/accountv2"
	"github.com/luiky/mock-bank/internal/api/app"
	"github.com/luiky/mock-bank/internal/api/consentv3"
	"github.com/luiky/mock-bank/internal/api/resourcev3"
	"github.com/luiky/mock-bank/internal/consent"
	"github.com/luiky/mock-bank/internal/directory"
	"github.com/luiky/mock-bank/internal/joseutil"
	"github.com/luiky/mock-bank/internal/oidc"
	"github.com/luiky/mock-bank/internal/resource"
	"github.com/luiky/mock-bank/internal/session"
	"github.com/luiky/mock-bank/internal/timeutil"
	"github.com/luiky/mock-bank/internal/user"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Environment string

const (
	LocalEnvironment Environment = "LOCAL"
)

var (
	Env                            = getEnv("ENV", LocalEnvironment)
	Host                           = getEnv("HOST", "https://mockbank.local")
	APPHost                        = strings.Replace(Host, "https://", "https://app.", 1)
	APIMTLSHost                    = strings.Replace(Host, "https://", "https://matls-api.", 1)
	AuthHost                       = strings.Replace(Host, "https://", "https://auth.", 1)
	AuthMTLSHost                   = strings.Replace(Host, "https://", "https://matls-auth.", 1)
	DirectoryIssuer                = getEnv("DIRECTORY_ISSUER", "https://directory.local")
	DirectoryClientID              = getEnv("DIRECTORY_CLIENT_ID", "mockbank")
	SoftwareStatementJWKSURL       = getEnv("SS_JWKS_URL", "https://keystore.local/openbanking.jwks")
	SoftwareStatementIssuer        = getEnv("SS_ISSUER", "Open Banking Open Banking Brasil sandbox SSA issuer")
	Port                           = getEnv("PORT", "80")
	DBConnectionString             = getEnv("DB_CONNECTION_STRING", "postgres://admin:pass@localhost:5432/mockbank?sslmode=disable")
	AWSEndpoint                    = getEnv("AWS_ENDPOINT", "http://localhost:4566")
	AWSRegion                      = getEnv("AWS_REGION", "us-east-1")
	OPKMSSigningKeyID              = getEnv("OP_KMS_SIGNING_KEY", "alias/mockbank/op-signing-key")
	DirectoryClientKMSSigningKeyID = getEnv("DIRECTORY_CLIENT_KMS_SIGNING_KEY", "alias/mockbank/directory-client-signing-key")
)

var Scopes = []goidc.Scope{
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
}

func main() {
	ctx := context.Background()

	// Defaults.
	http.DefaultClient = httpClient()
	slog.SetDefault(logger())

	// Database.
	db, err := dbConnection()
	if err != nil {
		log.Fatalf("failed connecting to database: %v", err)
	}

	// Keys.
	kmsClient := kmsClient()
	opSigner, err := joseutil.NewKMSSigner(ctx, OPKMSSigningKeyID, kmsClient)
	if err != nil {
		log.Fatalf("could not load kms signer for op: %v\n", err)
	}

	directoryClientSigner, err := joseutil.NewKMSSigner(ctx, DirectoryClientKMSSigningKeyID, kmsClient)
	if err != nil {
		log.Fatalf("could not load kms signer for directory: %v\n", err)
	}

	// Services.
	directoryService := directory.NewService(DirectoryIssuer, DirectoryClientID, APPHost+"/api/directory/callback", directoryClientSigner, httpClient())
	sessionService := session.NewService(db, directoryService)
	userService := user.NewService(db)
	consentService := consent.NewService(db, userService)
	resouceService := resource.NewService(db)
	accountService := account.NewService(db)

	op, err := openidProvider(db, opSigner, userService, consentService, accountService)
	if err != nil {
		log.Fatal(err)
	}

	// Servers.
	mux := http.NewServeMux()

	op.RegisterRoutes(mux)
	app.NewServer(APPHost, sessionService, directoryService, userService, consentService, resouceService, accountService).RegisterRoutes(mux)
	consentv3.NewServer(APIMTLSHost, consentService, op).RegisterRoutes(mux)
	resourcev3.NewServer(APIMTLSHost, resouceService, consentService, op).RegisterRoutes(mux)
	accountv2.NewServer(APIMTLSHost, accountService, consentService, op).RegisterRoutes(mux)

	if err := http.ListenAndServe(":"+Port, mux); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func dbConnection() (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(DBConnectionString), &gorm.Config{
		NowFunc: timeutil.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

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
					utcTime := timeutil.Now()
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

	if sessionID, ok := ctx.Value(api.CtxKeySessionID).(string); ok {
		r.AddAttrs(slog.String("session_id", sessionID))
	}

	return h.Handler.Handle(ctx, r)
}

func httpClient() *http.Client {
	tlsConfig := &tls.Config{}
	if Env == LocalEnvironment {
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
) (
	*provider.Provider,
	error,
) {

	// Get the file path of the source file.
	_, filename, _, _ := runtime.Caller(0)
	sourceDir := filepath.Dir(filename)

	templatesDirPath := filepath.Join(sourceDir, "../../templates")

	loginTemplate := filepath.Join(templatesDirPath, "/login.html")
	consentTemplate := filepath.Join(templatesDirPath, "/consent.html")
	tmpl, err := template.ParseFiles(loginTemplate, consentTemplate)
	if err != nil {
		log.Fatal(err)
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

	opts := []provider.ProviderOption{
		provider.WithClientStorage(oidc.NewClientManager(db)),
		provider.WithAuthnSessionStorage(oidc.NewAuthnSessionManager(db)),
		provider.WithGrantSessionStorage(oidc.NewGrantSessionManager(db)),
		provider.WithSignerFunc(func(ctx context.Context, alg goidc.SignatureAlgorithm) (kid string, s crypto.Signer, err error) {
			return "signer", signer, nil
		}),
		provider.WithScopes(Scopes...),
		provider.WithTokenOptions(oidc.TokenOptionsFunc()),
		provider.WithAuthorizationCodeGrant(),
		provider.WithImplicitGrant(),
		provider.WithRefreshTokenGrant(oidc.ShoudIssueRefreshToken, 600),
		provider.WithClientCredentialsGrant(),
		provider.WithTokenAuthnMethods(goidc.ClientAuthnPrivateKeyJWT),
		provider.WithPrivateKeyJWTSignatureAlgs(goidc.PS256),
		provider.WithMTLS(AuthMTLSHost, oidc.ClientCert),
		provider.WithTLSCertTokenBindingRequired(),
		provider.WithPAR(60),
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
		provider.WithHandleGrantFunc(oidc.HandleGrantFunc(op, consentService)),
		provider.WithPolicy(oidc.Policy(
			AuthHost,
			tmpl,
			userService,
			consentService,
			accountService,
		)),
		provider.WithNotifyErrorFunc(oidc.LogError),
		provider.WithDCR(oidc.DCRFunc(oidc.DCRConfig{
			Scopes:     Scopes,
			SSURL:      SoftwareStatementJWKSURL,
			SSIssuer:   SoftwareStatementIssuer,
			HTTPClient: httpClient(),
		}), nil),
	}
	if err := op.WithOptions(opts...); err != nil {
		return nil, err
	}

	return op, nil
}

func kmsClient() *kms.Client {
	kmsOpts := kms.Options{}
	if Env == LocalEnvironment {
		kmsOpts.Region = AWSRegion
		kmsOpts.Credentials = credentials.NewStaticCredentialsProvider("test", "test", "")
		kmsOpts.EndpointResolverV2 = localstackResolver{endpoint: AWSEndpoint}
	}

	return kms.New(kmsOpts)
}

type localstackResolver struct {
	endpoint string
}

func (r localstackResolver) ResolveEndpoint(ctx context.Context, params kms.EndpointParameters) (smithyendpoints.Endpoint, error) {
	uri, _ := url.Parse(r.endpoint)
	return smithyendpoints.Endpoint{
		URI: *uri,
	}, nil
}
