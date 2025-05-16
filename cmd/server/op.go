package main

import (
	"context"
	"encoding/json"
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
	// TODO: This will cause problems for the docker file.
	keysDir := filepath.Join(sourceDir, "../../keys")
	serverJWKS := privateJWKS(filepath.Join(keysDir, "server.jwks"))

	op, err := provider.New(
		goidc.ProfileFAPI1,
		authHost,
		func(_ context.Context) (goidc.JSONWebKeySet, error) {
			return serverJWKS, nil
		},
	)
	if err != nil {
		return nil, err
	}
	if err := op.WithOptions(
		// provider.WithClientStorage(oidc.NewClientManager(db)),
		// provider.WithAuthnSessionStorage(oidc.NewAuthnSessionManager(db)),
		// provider.WithGrantSessionStorage(oidc.NewGrantSessionManager(db)),
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
		provider.WithStaticClient(client("client_one", keysDir)),
		provider.WithStaticClient(client("client_two", keysDir)),
		provider.WithHandleGrantFunc(oidc.HandleGrantFunc(op, consentService)),
		provider.WithPolicy(oidc.Policy(templatesDirPath, authHost, userService,
			consentService, accountService)),
		provider.WithNotifyErrorFunc(oidc.LogError),
		provider.WithDCR(oidc.DCRFunc(oidc.DCRConfig{
			Scopes:     Scopes,
			SSURL:      ssJWKSURL,
			SSIssuer:   ssIssuer,
			HTTPClient: httpClient(),
		}), nil),
		provider.WithHTTPClientFunc(httpClientFunc()),
	); err != nil {
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
