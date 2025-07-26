package directory

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/mock-bank/internal/jwtutil"
	"github.com/luikyv/mock-bank/internal/timeutil"
)

var (
	cacheTime = 1 * time.Hour

	directoryWellKnownMu            sync.Mutex
	directoryWellKnownCache         *openIDConfiguration
	directoryWellKnownLastFetchedAt timeutil.DateTime

	directoryJWKSMu            sync.Mutex
	directoryJWKSCache         *goidc.JSONWebKeySet
	directoryJWKSLastFetchedAt timeutil.DateTime
)

type Service struct {
	issuer      string
	clientID    string
	redirectURI string
	jwtSigner   crypto.Signer
	mtlsClient  *http.Client
}

func NewService(issuer, clientID, redirectURI string, jwtSigner crypto.Signer, mtlsClient *http.Client) Service {
	return Service{
		issuer:      issuer,
		clientID:    clientID,
		redirectURI: redirectURI,
		jwtSigner:   jwtSigner,
		mtlsClient:  mtlsClient,
	}
}

func (ds Service) AuthURL(ctx context.Context) (uri, codeVerifier string, err error) {
	codeVerifier, codeChallenge := generateCodeVerifierAndChallenge()
	reqURI, err := ds.requestURI(ctx, codeChallenge)
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
	query.Set("response_type", "code")
	query.Set("scope", "openid trust_framework_profile")
	query.Set("redirect_uri", ds.redirectURI)
	authURL.RawQuery = query.Encode()
	return authURL.String(), codeVerifier, nil
}

func (s Service) IDToken(ctx context.Context, authCode, codeVerifier string) (IDToken, error) {
	idTkn, err := s.idToken(ctx, authCode, codeVerifier)
	if err != nil {
		return IDToken{}, err
	}

	wellKnown, err := s.wellKnown()
	if err != nil {
		return IDToken{}, fmt.Errorf("failed to fetch the directory well known for decoding id token: %w", err)
	}

	parsedIDTkn, err := jwt.ParseSigned(idTkn, wellKnown.IDTokenSigAlgs)
	if err != nil {
		return IDToken{}, fmt.Errorf("failed to parse id token: %w", err)
	}

	jwks, err := s.jwks()
	if err != nil {
		return IDToken{}, fmt.Errorf("failed to fetch jwks for verifying id token: %w", err)
	}

	var idToken IDToken
	var idTokenClaims jwt.Claims
	if err := parsedIDTkn.Claims(jwks.ToJOSE(), &idToken, &idTokenClaims); err != nil {
		return IDToken{}, fmt.Errorf("invalid id token signature: %w", err)
	}

	if idTokenClaims.IssuedAt == nil {
		return IDToken{}, errors.New("id token iat claim is missing")
	}

	if idTokenClaims.Expiry == nil {
		return IDToken{}, errors.New("id token exp claim is missing")
	}

	if err := idTokenClaims.Validate(jwt.Expected{
		Issuer:      s.issuer,
		AnyAudience: []string{s.clientID},
	}); err != nil {
		return IDToken{}, fmt.Errorf("invalid id token claims: %w", err)
	}

	return idToken, nil
}

func (s Service) idToken(ctx context.Context, authCode, codeVerifier string) (string, error) {
	wellKnown, err := s.wellKnown()
	if err != nil {
		return "", fmt.Errorf("failed to fetch the directory well known for requesting an id token: %w", err)
	}

	assertion, err := s.clientAssertion()
	if err != nil {
		return "", err
	}

	form := url.Values{}
	form.Set("client_id", s.clientID)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)
	form.Set("grant_type", "authorization_code")
	form.Set("code", authCode)
	form.Set("redirect_uri", s.redirectURI)
	form.Set("code_verifier", codeVerifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wellKnown.MTLS.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("error creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.mtlsClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		slog.Debug("error calling the token endpoint", "status_code", resp.StatusCode, "body", string(bodyBytes))
		return "", fmt.Errorf("token endpoint returned status %d", resp.StatusCode)
	}

	var result struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("error decoding token response: %w", err)
	}

	return result.IDToken, nil
}

func (ds Service) requestURI(ctx context.Context, codeChallenge string) (string, error) {
	wellKnown, err := ds.wellKnown()
	if err != nil {
		return "", err
	}

	assertion, err := ds.clientAssertion()
	if err != nil {
		return "", err
	}
	form := url.Values{}
	form.Set("client_id", ds.clientID)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)
	form.Set("response_type", "code")
	form.Set("scope", "openid trust_framework_profile")
	form.Set("redirect_uri", ds.redirectURI)
	form.Set("code_challenge", codeChallenge)
	form.Set("code_challenge_method", "S256")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wellKnown.MTLS.PushedAuthEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("error creating par request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := ds.mtlsClient.Do(req)
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

func (s Service) clientAssertion() (string, error) {
	wellKnown, err := s.wellKnown()
	if err != nil {
		return "", err
	}

	now := timeutil.Timestamp()
	claims := map[string]any{
		"iss": s.clientID,
		"sub": s.clientID,
		"aud": wellKnown.TokenEndpoint,
		"jti": uuid.NewString(),
		"iat": now,
		"exp": now + 300,
	}

	assertion, err := jwtutil.Sign(claims, s.jwtSigner)
	if err != nil {
		return "", fmt.Errorf("could not sign the client assertion: %w", err)
	}

	return assertion, nil
}

func (ds Service) wellKnown() (openIDConfiguration, error) {

	directoryWellKnownMu.Lock()
	defer directoryWellKnownMu.Unlock()

	if directoryWellKnownCache != nil && timeutil.DateTimeNow().Before(directoryWellKnownLastFetchedAt.Add(cacheTime)) {
		return *directoryWellKnownCache, nil
	}

	url := fmt.Sprintf("%s/.well-known/openid-configuration", ds.issuer)
	resp, err := ds.mtlsClient.Get(url)
	if err != nil {
		return openIDConfiguration{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return openIDConfiguration{}, fmt.Errorf("directory well known unexpected status code: %d", resp.StatusCode)
	}

	var config openIDConfiguration
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return openIDConfiguration{}, fmt.Errorf("failed to decode directory well known response: %w", err)
	}

	directoryWellKnownCache = &config
	directoryWellKnownLastFetchedAt = timeutil.DateTimeNow()
	return config, nil
}

func (ds Service) jwks() (goidc.JSONWebKeySet, error) {

	directoryJWKSMu.Lock()
	defer directoryJWKSMu.Unlock()

	if directoryJWKSCache != nil && timeutil.DateTimeNow().Before(directoryJWKSLastFetchedAt.Add(cacheTime)) {
		return *directoryJWKSCache, nil
	}

	wellKnown, err := ds.wellKnown()
	if err != nil {
		return goidc.JSONWebKeySet{}, err
	}

	resp, err := ds.mtlsClient.Get(wellKnown.JWKSURI)
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
	directoryJWKSLastFetchedAt = timeutil.DateTimeNow()
	return jwks, nil
}

func (ds Service) PublicJWKS() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			KeyID:     "signer",
			Algorithm: string(jose.PS256),
			Key:       ds.jwtSigner.Public(),
		}},
	}
}

func generateCodeVerifierAndChallenge() (verifier, challenge string) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	verifier = base64.RawURLEncoding.EncodeToString(b)
	hash := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(hash[:])
	return verifier, challenge
}
