package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
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
	issuer     string
	clientID   string
	httpClient *http.Client
}

func NewDirectoryService(issuer string, clientID string, httpClient *http.Client) DirectoryService {
	return DirectoryService{
		issuer:     issuer,
		clientID:   clientID,
		httpClient: httpClient,
	}
}

func (ds DirectoryService) authURL(_ context.Context) (string, error) {
	wellKnown, err := ds.wellKnown()
	if err != nil {
		return "", err
	}

	authURL, _ := url.Parse(wellKnown.AuthEndpoint)
	query := authURL.Query()
	query.Set("request_uri", "random_req_uri")
	authURL.RawQuery = query.Encode()

	return authURL.String(), nil
}

func (ds DirectoryService) idToken(_ context.Context, idTkn string) (directoryIDToken, error) {
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
		return directoryIDToken{}, fmt.Errorf("invalid id token: %w", err)
	}

	if idTokenClaims.Expiry == nil {
		return directoryIDToken{}, errors.New("id token expiration is missing")
	}

	if err := idTokenClaims.Validate(jwt.Expected{
		Issuer:      ds.issuer,
		AnyAudience: []string{ds.clientID},
	}); err != nil {
		return directoryIDToken{}, fmt.Errorf("invalid id token: %w", err)
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
