package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luiky/mock-bank/internal/timex"
)

var (
	directoryWellKnownMu            sync.Mutex
	directoryWellKnownCache         *directoryWellKnown
	directoryWellKnownLastFetchedAt time.Time

	directoryJWKSMu            sync.Mutex
	directoryJWKSCache         *jose.JSONWebKeySet
	directoryJWKSLastFetchedAt time.Time
)

type DirectoryService struct {
	issuer     string
	httpClient *http.Client
}

func NewDirectoryService(issuer string, httpClient *http.Client) DirectoryService {
	return DirectoryService{
		issuer:     issuer,
		httpClient: httpClient,
	}
}

func (DirectoryService) authURL(_ context.Context) (string, error) {
	return "random_auth_url", nil
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
	if err := parsedIDTkn.Claims(jwks, &idToken); err != nil {
		return directoryIDToken{}, fmt.Errorf("invalid id token: %w", err)
	}

	return idToken, nil
}

func (ds DirectoryService) wellKnown() (directoryWellKnown, error) {

	directoryWellKnownMu.Lock()
	defer directoryWellKnownMu.Unlock()

	if directoryWellKnownCache != nil && timex.Now().Before(directoryWellKnownLastFetchedAt.Add(1*time.Hour)) {
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

func (ds DirectoryService) jwks() (jose.JSONWebKeySet, error) {

	directoryJWKSMu.Lock()
	defer directoryJWKSMu.Unlock()

	if directoryJWKSCache != nil && timex.Now().Before(directoryJWKSLastFetchedAt.Add(1*time.Hour)) {
		return *directoryJWKSCache, nil
	}

	wellKnown, err := ds.wellKnown()
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}

	resp, err := ds.httpClient.Get(wellKnown.JWKSURI)
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return jose.JSONWebKeySet{}, fmt.Errorf("directory jwks unexpected status code: %d", resp.StatusCode)
	}

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("failed to decode directory jwks response: %w", err)
	}

	directoryJWKSCache = &jwks
	directoryJWKSLastFetchedAt = timex.Now()
	return jwks, nil
}
