package app

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/luiky/mock-bank/internal/joseutil"
	"github.com/luiky/mock-bank/internal/timex"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

var (
	cacheTime = 1 * time.Hour

	directoryWellKnownMu            sync.Mutex
	directoryWellKnownCache         *directoryWellKnown
	directoryWellKnownLastFetchedAt time.Time

	directoryJWKSMu            sync.Mutex
	directoryJWKSCache         *goidc.JSONWebKeySet
	directoryJWKSLastFetchedAt time.Time
)

type DirectoryService struct {
	issuer      string
	clientID    string
	redirectURI string
	signer      crypto.Signer
	httpClient  *http.Client
}

func NewDirectoryService(issuer, clientID, redirectURI string, signer crypto.Signer, httpClient *http.Client) DirectoryService {
	return DirectoryService{
		issuer:      issuer,
		clientID:    clientID,
		redirectURI: redirectURI,
		signer:      signer,
		httpClient:  httpClient,
	}
}

func (ds DirectoryService) authURL(ctx context.Context) (uri string, nonceHash string, err error) {
	nonce, nonceHash := generateNonce()
	reqURI, err := ds.requestURI(ctx, nonce)
	if err != nil {
		return "", "", err
	}

	wellKnown, err := ds.wellKnown()
	if err != nil {
		return "", "", err
	}

	authURL, _ := url.Parse(wellKnown.AuthEndpoint)
	query := authURL.Query()
	query.Set("client_id", ds.clientID)
	query.Set("request_uri", reqURI)
	query.Set("response_type", "id_token")
	query.Set("scope", "openid")
	query.Set("redirect_uri", ds.redirectURI)
	query.Set("nonce", nonce)
	authURL.RawQuery = query.Encode()
	return authURL.String(), nonceHash, nil
}

func (ds DirectoryService) requestURI(ctx context.Context, nonce string) (string, error) {
	wellKnown, err := ds.wellKnown()
	if err != nil {
		return "", err
	}

	now := timex.Timestamp()
	claims := map[string]any{
		"iss": ds.clientID,
		"sub": ds.clientID,
		"aud": wellKnown.PushedAuthEndpoint,
		"jti": uuid.NewString(),
		"iat": now,
		"exp": now + 300,
	}

	clientAssertion, err := joseutil.Sign(claims, ds.signer)
	if err != nil {
		return "", fmt.Errorf("could not sign the client assertion")
	}

	form := url.Values{}
	form.Set("client_id", ds.clientID)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", clientAssertion)
	form.Set("response_type", "id_token")
	form.Set("scope", "openid")
	form.Set("redirect_uri", ds.redirectURI)
	form.Set("nonce", nonce)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wellKnown.PushedAuthEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("error creating par request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := ds.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("par request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("par endpoint returned status %d", resp.StatusCode)
	}

	var result struct {
		RequestURI string `json:"request_uri"`
		ExpiresIn  int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("error decoding par response: %w", err)
	}

	return result.RequestURI, nil
}

func (ds DirectoryService) idToken(_ context.Context, idTkn, nonceHash string) (directoryIDToken, error) {
	wellKnown, err := ds.wellKnown()
	if err != nil {
		return directoryIDToken{}, fmt.Errorf("failed to fetch the directory well known for decoding id token: %w", err)
	}

	parsedIDTkn, err := jwt.ParseSigned(idTkn, wellKnown.IDTokenSigAlgs)
	if err != nil {
		return directoryIDToken{}, fmt.Errorf("failed to parse id token: %w", err)
	}

	jwks, err := ds.jwks()
	if err != nil {
		return directoryIDToken{}, fmt.Errorf("failed to fetch jwks for verifying id token: %w", err)
	}

	var idToken directoryIDToken
	var idTokenClaims jwt.Claims
	if err := parsedIDTkn.Claims(jwks.ToJOSE(), &idToken, &idTokenClaims); err != nil {
		return directoryIDToken{}, fmt.Errorf("invalid id token signature: %w", err)
	}

	if idTokenClaims.IssuedAt == nil {
		return directoryIDToken{}, errors.New("id token iat claim is missing")
	}

	if idTokenClaims.Expiry == nil {
		return directoryIDToken{}, errors.New("id token exp claim is missing")
	}

	if err := idTokenClaims.Validate(jwt.Expected{
		Issuer:      ds.issuer,
		AnyAudience: []string{ds.clientID},
	}); err != nil {
		return directoryIDToken{}, fmt.Errorf("invalid id token claims: %w", err)
	}

	h := sha256.Sum256([]byte(idToken.Nonce))
	if nonceHash != hex.EncodeToString(h[:]) {
		return directoryIDToken{}, fmt.Errorf("invalid id token nonce")
	}

	return idToken, nil
}

func (ds DirectoryService) wellKnown() (directoryWellKnown, error) {

	directoryWellKnownMu.Lock()
	defer directoryWellKnownMu.Unlock()

	if directoryWellKnownCache != nil && timex.Now().Before(directoryWellKnownLastFetchedAt.Add(cacheTime)) {
		return *directoryWellKnownCache, nil
	}

	url := fmt.Sprintf("%s/.well-known/openid-configuration", ds.issuer)
	resp, err := ds.httpClient.Get(url)
	if err != nil {
		return directoryWellKnown{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return directoryWellKnown{}, fmt.Errorf("directory well known unexpected status code: %d", resp.StatusCode)
	}

	var config directoryWellKnown
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return directoryWellKnown{}, fmt.Errorf("failed to decode directory well known response: %w", err)
	}

	directoryWellKnownCache = &config
	directoryWellKnownLastFetchedAt = timex.Now()
	return config, nil
}

func (ds DirectoryService) jwks() (goidc.JSONWebKeySet, error) {

	directoryJWKSMu.Lock()
	defer directoryJWKSMu.Unlock()

	if directoryJWKSCache != nil && timex.Now().Before(directoryJWKSLastFetchedAt.Add(cacheTime)) {
		return *directoryJWKSCache, nil
	}

	wellKnown, err := ds.wellKnown()
	if err != nil {
		return goidc.JSONWebKeySet{}, err
	}

	resp, err := ds.httpClient.Get(wellKnown.JWKSURI)
	if err != nil {
		return goidc.JSONWebKeySet{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return goidc.JSONWebKeySet{}, fmt.Errorf("directory jwks unexpected status code: %d", resp.StatusCode)
	}

	var jwks goidc.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return goidc.JSONWebKeySet{}, fmt.Errorf("failed to decode directory jwks response: %w", err)
	}

	directoryJWKSCache = &jwks
	directoryJWKSLastFetchedAt = timex.Now()
	return jwks, nil
}

func (ds DirectoryService) publicJWKS() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			KeyID:     "signer",
			Algorithm: string(jose.PS256),
			Key:       ds.signer.Public(),
		}},
	}
}

func generateNonce() (nonce, nonceHash string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)

	nonce = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(nonce))
	return nonce, hex.EncodeToString(h[:])
}
