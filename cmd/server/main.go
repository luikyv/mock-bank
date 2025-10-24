package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"time"

	"github.com/luikyv/mock-bank/cmd/cmdutil"
	accountapi "github.com/luikyv/mock-bank/internal/api/account"
	"github.com/luikyv/mock-bank/internal/api/app"
	autopaymentapi "github.com/luikyv/mock-bank/internal/api/autopayment"
	consentapi "github.com/luikyv/mock-bank/internal/api/consent"
	creditportabilityapi "github.com/luikyv/mock-bank/internal/api/creditportability"
	enrollmentapi "github.com/luikyv/mock-bank/internal/api/enrollment"
	loanapi "github.com/luikyv/mock-bank/internal/api/loan"
	oidcapi "github.com/luikyv/mock-bank/internal/api/oidc"
	paymentapi "github.com/luikyv/mock-bank/internal/api/payment"
	resourceapi "github.com/luikyv/mock-bank/internal/api/resource"
	"github.com/luikyv/mock-bank/internal/client"
	"github.com/luikyv/mock-bank/internal/creditop"
	"github.com/luikyv/mock-bank/internal/creditportability"
	"github.com/luikyv/mock-bank/internal/customer"
	"github.com/luikyv/mock-bank/internal/enrollment"
	"github.com/luikyv/mock-bank/internal/idempotency"
	"github.com/luikyv/mock-bank/internal/jwtutil"
	"github.com/luikyv/mock-bank/internal/session"
	"github.com/luikyv/mock-bank/internal/webhook"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
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
	"gorm.io/gorm"
)

const (
	Brand             string = "MockBank"
	CNPJ              string = "00000000000000"
	ISPB              string = "00000000"
	IBGETownCode      string = "0000000"
	Currency          string = "BRL"
	AccountCompeCode  string = "001"
	AccountBranch     string = "0001"
	AccountCheckDigit string = "1"
)

var (
	Env = cmdutil.EnvValue("ENV", cmdutil.LocalEnvironment)
	// OrgID is the Mock Bank organization identifier.
	OrgID        = cmdutil.EnvValue("ORG_ID", "00000000-0000-0000-0000-000000000000")
	BaseDomain   = cmdutil.EnvValue("BASE_DOMAIN", "mockbank.local")
	APPHost      = "https://app." + BaseDomain
	APIMTLSHost  = "https://matls-api." + BaseDomain
	AuthHost     = "https://auth." + BaseDomain
	AuthMTLSHost = "https://matls-auth." + BaseDomain
	// DirectoryIssuer is the issuer used by the directory to sign ID tokens, etc.
	DirectoryIssuer = cmdutil.EnvValue("DIRECTORY_ISSUER", "https://directory.local")
	// DirectoryClientID is the client ID for Mock Bank to make OAuth requests to the directory.
	DirectoryClientID       = cmdutil.EnvValue("DIRECTORY_CLIENT_ID", "mockbank")
	KeyStoreHost            = cmdutil.EnvValue("KEYSTORE_HOST", "https://keystore.local")
	SoftwareStatementIssuer = cmdutil.EnvValue("SS_ISSUER", "Open Banking Brasil sandbox SSA issuer")
	Port                    = cmdutil.EnvValue("PORT", "80")
	DBSecretName            = cmdutil.EnvValue("DB_SECRET_NAME", "mockbank/db-credentials")
	// OPSigningKeySSMParamName is the parameter used to sign JWTs for the OpenID Provider.
	OPSigningKeySSMParamName = cmdutil.EnvValue("OP_SIGNING_KEY_SSM_PARAM", "/mockbank/op-signing-key")
	// DirectoryClientSigningKeySSMParamName is the parameter used to sign JWTs for the directory client.
	DirectoryClientSigningKeySSMParamName = cmdutil.EnvValue("DIRECTORY_CLIENT_SIGNING_KEY_SSM_PARAM", "/mockbank/directory-client-signing-key")
	// DirectoryClientMTLSCertSSMParamName and DirectoryClientMTLSKeySSMParamName are the parameters used for mutual TLS connection with the directory.
	DirectoryClientMTLSCertSSMParamName = cmdutil.EnvValue("DIRECTORY_CLIENT_MTLS_CERT_SSM_PARAM", "/mockbank/directory-client-transport-cert")
	DirectoryClientMTLSKeySSMParamName  = cmdutil.EnvValue("DIRECTORY_CLIENT_MTLS_KEY_SSM_PARAM", "/mockbank/directory-client-transport-key")
	// OrgSigningKeySSMParamName is the parameter used by Mock Bank to sign API responses.
	OrgSigningKeySSMParamName = cmdutil.EnvValue("ORG_SIGNING_KEY_SSM_PARAM", "/mockbank/org-signing-key")
	// TransportCertSSMParamName and TransportKeySSMParamName are the parameters used for mutual TLS connection with the webhook client.
	TransportCertSSMParamName = cmdutil.EnvValue("TRANSPORT_CERT_SSM_PARAM", "/mockbank/transport-cert")
	TransportKeySSMParamName  = cmdutil.EnvValue("TRANSPORT_KEY_SSM_PARAM", "/mockbank/transport-key")
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	slog.SetDefault(logger())
	slog.Info("setting up mock bank", "env", Env)
	http.DefaultClient = httpClient()
	awsConfig, err := cmdutil.AWSConfig(ctx, Env)
	if err != nil {
		slog.Error("failed to load aws config", "error", err)
		os.Exit(1)
	}
	bankConfig := BankConfig{
		host:              APIMTLSHost,
		orgID:             OrgID,
		brand:             Brand,
		cnpj:              CNPJ,
		ispb:              ISPB,
		ibgeTownCode:      IBGETownCode,
		currency:          Currency,
		accountCompeCode:  AccountCompeCode,
		accountBranch:     AccountBranch,
		accountCheckDigit: AccountCheckDigit,
	}

	// Database.
	slog.Info("creating secrets manager client")
	secretsClient := secretsmanager.NewFromConfig(*awsConfig)
	slog.Info("secrets manager client created")
	db, err := cmdutil.DB(ctx, secretsClient, DBSecretName)
	if err != nil {
		slog.Error("failed connecting to database", "error", err)
		os.Exit(1)
	}

	// Keys.
	slog.Info("creating ssm client")
	ssmClient := ssm.NewFromConfig(*awsConfig)
	slog.Info("ssm client created")

	opSigner, err := signerFromSSM(ctx, ssmClient, OPSigningKeySSMParamName)
	if err != nil {
		slog.Error("could not load signer for op", "error", err)
		os.Exit(1)
	}

	directoryClientSigner, err := signerFromSSM(ctx, ssmClient, DirectoryClientSigningKeySSMParamName)
	if err != nil {
		slog.Error("could not load signer for directory", "error", err)
		os.Exit(1)
	}

	directoryClientTLSCert, err := cmdutil.TLSCertFromSSM(ctx, ssmClient, DirectoryClientMTLSCertSSMParamName, DirectoryClientMTLSKeySSMParamName)
	if err != nil {
		slog.Error("could not load directory client TLS certificate", "error", err)
		os.Exit(1)
	}

	orgSigner, err := signerFromSSM(ctx, ssmClient, OrgSigningKeySSMParamName)
	if err != nil {
		slog.Error("could not load signer for organization", "error", err)
		os.Exit(1)
	}

	transportTLSCert, err := cmdutil.TLSCertFromSSM(ctx, ssmClient, TransportCertSSMParamName, TransportKeySSMParamName)
	if err != nil {
		slog.Error("could not load transport TLS certificate", "error", err)
		os.Exit(1)
	}

	// Services.
	sessionService := session.NewService(db, DirectoryIssuer, DirectoryClientID, APPHost+"/api/directory/callback",
		directoryClientSigner, cmdutil.MTLSHTTPClient(directoryClientTLSCert, Env))
	clientService := client.NewService(db)
	idempotencyService := idempotency.NewService(db)
	jwtService := jwtutil.NewService(db)
	webhookService := webhook.NewService(clientService, cmdutil.MTLSHTTPClient(transportTLSCert, Env))
	userService := user.NewService(db, OrgID)
	resourceService := resource.NewService(db)
	consentService := consent.NewService(db, userService, resourceService)
	accountService := account.NewService(db, OrgID)
	creditOpService := creditop.NewService(db, OrgID)
	paymentService := payment.NewService(db, userService, accountService, webhookService)
	autoPaymentService := autopayment.NewService(db, userService, accountService, webhookService)
	enrollmentService := enrollment.NewService(db, userService, accountService, paymentService, autoPaymentService, webhookService)
	creditPortabilityService := creditportability.NewService(db, creditOpService)

	op, err := openidProvider(db, opSigner, clientService, userService, consentService, accountService,
		creditOpService, paymentService, autoPaymentService, enrollmentService)
	if err != nil {
		slog.Error("failed to create openid provider", "error", err)
		os.Exit(1)
	}

	// Servers.
	mux := http.NewServeMux()

	oidcapi.NewServer(AuthHost, op).RegisterRoutes(mux)
	app.NewServer(bankConfig, APPHost, sessionService, userService, consentService, resourceService, accountService, enrollmentService).RegisterRoutes(mux)
	consentapi.NewServer(bankConfig, consentService, op).RegisterRoutes(mux)
	resourceapi.NewServer(bankConfig, resourceService, consentService, op).RegisterRoutes(mux)
	accountapi.NewServer(APIMTLSHost, accountService, consentService, op).RegisterRoutes(mux)
	loanapi.NewServer(bankConfig, creditOpService, consentService, op).RegisterRoutes(mux)
	paymentapi.NewServer(bankConfig, paymentService, idempotencyService, jwtService, op, KeyStoreHost, OrgID, orgSigner).RegisterRoutes(mux)
	autopaymentapi.NewServer(bankConfig, autoPaymentService, idempotencyService, jwtService, op, KeyStoreHost, OrgID, orgSigner).RegisterRoutes(mux)
	enrollmentapi.NewServer(bankConfig, enrollmentService, idempotencyService, jwtService, op, KeyStoreHost, OrgID, orgSigner).RegisterRoutes(mux)
	creditportabilityapi.NewServer(bankConfig, creditPortabilityService, consentService, idempotencyService, jwtService, op, KeyStoreHost, OrgID, orgSigner).RegisterRoutes(mux)

	handler := middleware(mux)
	slog.Info("starting mock bank")

	if err := http.ListenAndServe(":"+Port, handler); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("failed to start mock bank", "error", err)
		os.Exit(1)
	}
}

type BankConfig struct {
	host              string
	orgID             string
	brand             string
	cnpj              string
	ispb              string
	ibgeTownCode      string
	currency          string
	accountCompeCode  string
	accountBranch     string
	accountCheckDigit string
}

func (bc BankConfig) Host() string {
	return bc.host
}

func (bc BankConfig) OrgID() string {
	return bc.orgID
}

func (bc BankConfig) Brand() string {
	return bc.brand
}

func (bc BankConfig) CNPJ() string {
	return bc.cnpj
}

func (bc BankConfig) ISPB() string {
	return bc.ispb
}

func (bc BankConfig) IBGETownCode() string {
	return bc.ibgeTownCode
}

func (bc BankConfig) Currency() string {
	return bc.currency
}

func (bc BankConfig) AccountCompeCode() string {
	return bc.accountCompeCode
}

func (bc BankConfig) AccountBranch() string {
	return bc.accountBranch
}

func (bc BankConfig) AccountCheckDigit() string {
	return bc.accountCheckDigit
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
	tlsConfig := &tls.Config{
		Renegotiation: tls.RenegotiateOnceAsClient,
	}
	if Env == cmdutil.LocalEnvironment {
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
	clientService client.Service,
	userService user.Service,
	consentService consent.Service,
	accountService account.Service,
	creditOpService creditop.Service,
	paymentService payment.Service,
	autoPaymentService autopayment.Service,
	enrollmentService enrollment.Service,
) (*provider.Provider, error) {
	var scopes = []goidc.Scope{
		goidc.ScopeOpenID,
		consent.ScopeID,
		consent.Scope,
		customer.Scope,
		account.Scope,
		// creditcard.Scope,
		creditop.ScopeLoans,
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
		enrollment.ScopeConsent,
		enrollment.ScopeID,
		creditportability.Scope,
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
		provider.WithClientStorage(oidc.NewClientManager(clientService)),
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
		provider.WithUnregisteredRedirectURIsForPAR(),
		provider.WithUnregisteredRedirectURIsForPAR(),
		provider.WithJAR(goidc.PS256),
		provider.WithJAREncryption(goidc.RSA_OAEP),
		provider.WithJARContentEncryptionAlgs(goidc.A256GCM),
		provider.WithJARM(goidc.PS256),
		provider.WithIssuerResponseParameter(),
		provider.WithPKCE(goidc.CodeChallengeMethodSHA256),
		provider.WithACRs(oidc.ACROpenBankingLOA2, oidc.ACROpenBankingLOA3),
		provider.WithUserInfoSignatureAlgs(goidc.PS256),
		provider.WithUserInfoEncryption(goidc.RSA_OAEP),
		provider.WithUserInfoContentEncryptionAlgs(goidc.A256GCM),
		provider.WithIDTokenSignatureAlgs(goidc.PS256),
		provider.WithIDTokenEncryption(goidc.RSA_OAEP),
		provider.WithIDTokenContentEncryptionAlgs(goidc.A256GCM),
		provider.WithHandleGrantFunc(oidc.HandleGrantFunc(op, consentService, paymentService, autoPaymentService, enrollmentService)),
		provider.WithPolicies(oidc.Policies(AuthHost, userService, consentService, accountService, creditOpService, paymentService, autoPaymentService, enrollmentService)...),
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

func middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = context.WithValue(ctx, api.CtxKeyCorrelationID, uuid.NewString())
		if fapiID := r.Header.Get("X-Fapi-Interaction-Id"); fapiID != "" {
			ctx = context.WithValue(ctx, api.CtxKeyInteractionID, fapiID)
		}
		slog.InfoContext(ctx, "request received", "method", r.Method, "path", r.URL.Path)

		start := timeutil.DateTimeNow()
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic recovered", "error", rec, "stack", string(debug.Stack()))
				api.WriteError(w, r, fmt.Errorf("internal error: %v", rec))
			}
			slog.InfoContext(ctx, "request completed", slog.Duration("duration", time.Since(start.Time)))
		}()

		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}
