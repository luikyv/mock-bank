package main

import (
	"context"
	"crypto"
	"encoding/json"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/luiky/mock-bank/internal/opf/account"
	"github.com/luiky/mock-bank/internal/opf/consent"
	"github.com/luiky/mock-bank/internal/opf/oidc"
	"github.com/luiky/mock-bank/internal/opf/resource"
	"github.com/luiky/mock-bank/internal/opf/user"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
	"gorm.io/gorm"
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

func httpClientFunc() goidc.HTTPClientFunc {
	return func(ctx context.Context) *http.Client {
		return httpClient()
	}
}
