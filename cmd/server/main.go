package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

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
	env                = getEnv("ENV", LocalEnvironment)
	orgID              = getEnv("ORG_ID", "00000000-0000-0000-0000-000000000000")
	host               = getEnv("HOST", "https://mockbank.local")
	appHost            = strings.Replace(host, "https://", "https://app.", 1)
	apiMTLSHost        = strings.Replace(host, "https://", "https://matls-api.", 1)
	authHost           = strings.Replace(host, "https://", "https://auth.", 1)
	authMTLSHost       = strings.Replace(host, "https://", "https://matls-auth.", 1)
	directoryIssuer    = getEnv("DIRECTORY_ISSUER", "https://directory.local")
	directoryClientID  = getEnv("DIRECTORY_CLIENT_ID", "mockbank")
	ssJWKSURL          = getEnv("SS_JWKS_URL", "https://keystore.local/openbanking.jwks")
	ssIssuer           = getEnv("SS_ISSUER", "Open Banking Open Banking Brasil sandbox SSA issuer")
	port               = getEnv("PORT", "80")
	dbConnectionString = getEnv("DB_CONNECTION_STRING", "postgres://admin:pass@localhost:5432/mockbank?sslmode=disable")
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
	// Logging.
	slog.SetDefault(logger())

	// Database.
	db, err := dbConnection()
	if err != nil {
		log.Fatalf("failed to connect mongo database: %v", err)
	}

	// Keys.
	opSigner := joseutil.NewSigner()
	directorySigner := joseutil.NewSigner()

	// Services.
	directoryService := directory.NewService(directoryIssuer, directoryClientID, appHost+"/api/directory/callback", directorySigner, httpClient())
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
	app.NewServer(appHost, sessionService, directoryService, userService, consentService, resouceService, accountService).RegisterRoutes(mux)
	consentv3.NewServer(apiMTLSHost, consentService, op).RegisterRoutes(mux)
	resourcev3.NewServer(apiMTLSHost, resouceService, consentService, op).RegisterRoutes(mux)
	accountv2.NewServer(apiMTLSHost, accountService, consentService, op).RegisterRoutes(mux)

	if err := http.ListenAndServe(":"+port, mux); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func dbConnection() (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(dbConnectionString), &gorm.Config{
		NowFunc: timeutil.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	return db, nil
}

// getEnv retrieves an environment variable or returns a fallback value if not found
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

	if orgID, ok := ctx.Value(app.CtxKeyOrgID).(string); ok {
		r.AddAttrs(slog.String("org_id", orgID))
	}

	if interactionID, ok := ctx.Value(app.CtxKeyInteractionID).(string); ok {
		r.AddAttrs(slog.String("interaction_id", interactionID))
	}

	if sessionID, ok := ctx.Value(app.CtxKeySessionID).(string); ok {
		r.AddAttrs(slog.String("session_id", sessionID))
	}

	return h.Handler.Handle(ctx, r)
}

func httpClient() *http.Client {
	tlsConfig := &tls.Config{}
	if env == LocalEnvironment {
		tlsConfig.InsecureSkipVerify = true
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
}

func openidProvider(
	_ *gorm.DB,
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

	op, err := provider.New(goidc.ProfileFAPI1, authHost, func(_ context.Context) (goidc.JSONWebKeySet, error) {
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
		// TODO.
		// provider.WithClientStorage(oidc.NewClientManager(db)),
		// provider.WithAuthnSessionStorage(oidc.NewAuthnSessionManager(db)),
		// provider.WithGrantSessionStorage(oidc.NewGrantSessionManager(db)),
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
		provider.WithMTLS(authMTLSHost, oidc.ClientCert),
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
		provider.WithPolicy(oidc.Policy(authHost, tmpl, userService,
			consentService, accountService)),
		provider.WithNotifyErrorFunc(oidc.LogError),
		provider.WithDCR(oidc.DCRFunc(oidc.DCRConfig{
			Scopes:     Scopes,
			SSURL:      ssJWKSURL,
			SSIssuer:   ssIssuer,
			HTTPClient: httpClient(),
		}), nil),
		provider.WithHTTPClientFunc(httpClientFunc()),
	}
	if env == LocalEnvironment {
		// TODO: Seed the db instead.
		keysDir := filepath.Join(sourceDir, "../../keys")
		opts = append(opts, provider.WithStaticClient(client("client_one", keysDir)),
			provider.WithStaticClient(client("client_two", keysDir)))
	}
	if err := op.WithOptions(opts...); err != nil {
		return nil, err
	}

	return op, nil
}

func client(clientID string, keysDir string) *goidc.Client {
	var scopes []string
	for _, scope := range Scopes {
		scopes = append(scopes, scope.ID)
	}

	privateJWKS := privateJWKS(filepath.Join(keysDir, clientID+".jwks"))
	publicJWKS := privateJWKS.Public()
	return &goidc.Client{
		ID: clientID,
		ClientMeta: goidc.ClientMeta{
			TokenAuthnMethod: goidc.ClientAuthnPrivateKeyJWT,
			ScopeIDs:         strings.Join(scopes, " "),
			RedirectURIs: []string{
				"https://localhost.emobix.co.uk:8443/test/a/mockbank/callback",
			},
			GrantTypes: []goidc.GrantType{
				goidc.GrantAuthorizationCode,
				goidc.GrantRefreshToken,
				goidc.GrantClientCredentials,
				goidc.GrantImplicit,
			},
			ResponseTypes: []goidc.ResponseType{
				goidc.ResponseTypeCode,
				goidc.ResponseTypeCodeAndIDToken,
			},
			PublicJWKS:           &publicJWKS,
			IDTokenKeyEncAlg:     goidc.RSA_OAEP,
			IDTokenContentEncAlg: goidc.A128CBC_HS256,
			CustomAttributes: map[string]any{
				oidc.ClientAttrOrgID: orgID,
			},
		},
	}
}

func privateJWKS(filePath string) goidc.JSONWebKeySet {
	absPath, _ := filepath.Abs(filePath)
	jwksFile, err := os.Open(absPath)
	if err != nil {
		log.Fatal(err)
	}
	defer jwksFile.Close()

	jwksBytes, err := io.ReadAll(jwksFile)
	if err != nil {
		log.Fatal(err)
	}

	var jwks goidc.JSONWebKeySet
	if err := json.Unmarshal(jwksBytes, &jwks); err != nil {
		log.Fatal(err)
	}

	return jwks
}

// TODO: Move this to oidc.
func httpClientFunc() goidc.HTTPClientFunc {
	return func(ctx context.Context) *http.Client {
		return httpClient()
	}
}
