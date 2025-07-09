package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func main() {
	// Load and parse the directory JWKS.
	directoryJWKSBytes, err := os.ReadFile("/mocks/directory_jwks.json")
	if err != nil {
		log.Fatal("failed to read directory jwks:", err)
	}
	var directoryJWKS jose.JSONWebKeySet
	if err := json.Unmarshal(directoryJWKSBytes, &directoryJWKS); err != nil {
		log.Fatal("failed to parse directory jwks:", err)
	}

	// Load and parse the keystore JWKS.
	keystoreJWKSBytes, err := os.ReadFile("/mocks/software_statement_jwks.json")
	if err != nil {
		log.Fatal("failed to read keystore jwks:", err)
	}
	var keystoreJWKS jose.JSONWebKeySet
	if err := json.Unmarshal(keystoreJWKSBytes, &keystoreJWKS); err != nil {
		log.Fatal("failed to parse keystore jwks:", err)
	}

	// Load and parse the participant ID token.
	idTokenBytes, err := os.ReadFile("/mocks/id_token.json")
	if err != nil {
		log.Fatal("failed to read id token:", err)
	}
	var idTokenClaims map[string]any
	_ = json.Unmarshal(idTokenBytes, &idTokenClaims)

	// Load and parse the software statement.
	ssBytes, err := os.ReadFile("/mocks/software_statement.json")
	if err != nil {
		log.Fatal("failed to read id token:", err)
	}
	var ssClaims map[string]any
	_ = json.Unmarshal(ssBytes, &ssClaims)

	// Define routes.

	directoryHandler := func() http.Handler {
		mux := http.NewServeMux()

		mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
			log.Println("request directory openid configuration")
			w.Header().Set("Content-Type", "application/json")
			http.ServeFile(w, r, "/mocks/directory_well_known.json")
		})

		mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
			log.Println("request directory jwks")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			var jwks jose.JSONWebKeySet
			for _, key := range directoryJWKS.Keys {
				jwks.Keys = append(jwks.Keys, key.Public())
			}
			_ = json.NewEncoder(w).Encode(jwks)
		})

		mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
			log.Println("request directory authorize")
			http.Redirect(w, r, "https://app.mockbank.local/api/directory/callback?code=random_code", http.StatusSeeOther)
		})

		mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
			log.Println("request directory token")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)

			grantType := r.FormValue("grant_type")
			if grantType == "client_credentials" {
				_, _ = io.WriteString(w, `{
					"access_token": "random_token",
					"token_type": "bearer"
				}`)
				return
			}

			key := directoryJWKS.Keys[0]
			joseSigner, _ := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(key.Algorithm),
				Key:       key,
			}, (&jose.SignerOptions{}).WithType("JWT"))

			idTokenClaims["iat"] = time.Now().Unix()
			idTokenClaims["exp"] = time.Now().Unix() + 60
			idToken, _ := jwt.Signed(joseSigner).Claims(idTokenClaims).Serialize()

			_, _ = io.WriteString(w, fmt.Sprintf(`{
				"access_token": "random_token",
				"id_token": "%s",
				"token_type": "bearer"
			}`, idToken))
		})

		mux.HandleFunc("POST /par", func(w http.ResponseWriter, r *http.Request) {
			log.Println("request directory par")

			_ = r.ParseForm()

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{
				"request_uri": "urn:ietf:params:oauth:request_uri:random_uri",
				"expires_in": 60
			}`)
		})

		mux.HandleFunc("GET /participants", func(w http.ResponseWriter, r *http.Request) {
			log.Println("request directory participants")
			w.Header().Set("Content-Type", "application/json")
			http.ServeFile(w, r, "/mocks/participants.json")
		})

		mux.HandleFunc("GET /organisations/{org_id}/softwarestatements/{ss_id}/assertion", func(w http.ResponseWriter, r *http.Request) {
			log.Println("request directory software statement")
			key := keystoreJWKS.Keys[0]
			joseSigner, _ := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(key.Algorithm),
				Key:       key,
			}, (&jose.SignerOptions{}).WithType("JWT"))

			ssClaims["iat"] = time.Now().Unix()
			ssa, _ := jwt.Signed(joseSigner).Claims(ssClaims).Serialize()

			w.Header().Set("Content-Type", "application/jwt")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, ssa)
		})

		return mux
	}

	keystoreHandler := func() http.Handler {
		mux := http.NewServeMux()

		mux.HandleFunc("GET /{org_id}/{software_id}/application.jwks", func(w http.ResponseWriter, r *http.Request) {
			log.Println("request keystore client jwks")
			w.Header().Set("Content-Type", "application/json")
			http.ServeFile(w, r, "/mocks/client.jwks")
		})

		mux.HandleFunc("GET /{org_id}/application.jwks", func(w http.ResponseWriter, r *http.Request) {
			log.Println("request keystore organization jwks")
			w.Header().Set("Content-Type", "application/json")
			http.ServeFile(w, r, "/mocks/org.jwks")
		})

		mux.HandleFunc("GET /openbanking.jwks", func(w http.ResponseWriter, r *http.Request) {
			log.Println("request keystore open banking jwks")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			var jwks jose.JSONWebKeySet
			for _, key := range keystoreJWKS.Keys {
				jwks.Keys = append(jwks.Keys, key.Public())
			}
			_ = json.NewEncoder(w).Encode(jwks)
		})

		return mux
	}

	mux := http.NewServeMux()

	mux.Handle("directory.local/", directoryHandler())
	mux.Handle("matls-directory.local/", directoryHandler())

	mux.Handle("keystore.local/", keystoreHandler())
	mux.Handle("matls-keystore.local/", keystoreHandler())

	// Mock Bank backend can be accessed from the host machine for local development.
	// If the connection is refused, fallback to the container.
	mockbankLocalhostURL, _ := url.Parse("http://host.docker.internal")
	mockbankLocalhostReverseProxy := httputil.NewSingleHostReverseProxy(mockbankLocalhostURL)
	mockbankURL, _ := url.Parse("http://mockbank")
	mockbankReverseProxy := httputil.NewSingleHostReverseProxy(mockbankURL)
	mbHandler := reverseProxyWithFallback(mockbankLocalhostReverseProxy, mockbankReverseProxy)
	mux.HandleFunc("auth.mockbank.local/", mbHandler)
	mux.HandleFunc("matls-auth.mockbank.local/", mbHandler)
	mux.HandleFunc("matls-api.mockbank.local/", mbHandler)
	mux.HandleFunc("app.mockbank.local/api/", mbHandler)

	// Mock Bank frontend can be accessed from the host machine for local development.
	// If the connection is refused, fallback to the container.
	mockbankAppLocalhostURL, _ := url.Parse("http://host.docker.internal:8080")
	mockbankAppLocalhostReverseProxy := httputil.NewSingleHostReverseProxy(mockbankAppLocalhostURL)
	mockbankAppURL, _ := url.Parse("http://mockbank-ui:8080")
	mockbankAppReverseProxy := httputil.NewSingleHostReverseProxy(mockbankAppURL)
	mbAppHandler := reverseProxyWithFallback(mockbankAppLocalhostReverseProxy, mockbankAppReverseProxy)
	mux.Handle("app.mockbank.local/", mbAppHandler)

	// Serve participant information over HTTP because the Conformance Suite
	// does not accept self-signed certificates.
	http.HandleFunc("GET directory.local/participants", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		http.ServeFile(w, r, "/mocks/participants.json")
	})
	go func() {
		if err := http.ListenAndServe(":80", nil); err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	caCertPEM, err := os.ReadFile("/mocks/ca.crt")
	if err != nil {
		log.Fatal("Failed to read CA file:", err)
	}
	caPool := x509.NewCertPool()
	if ok := caPool.AppendCertsFromPEM(caCertPEM); !ok {
		log.Fatal("Failed to append CA certs")
	}
	serverCert, err := tls.LoadX509KeyPair("/mocks/server.crt", "/mocks/server.key")
	if err != nil {
		log.Fatalf("failed to load server certificate: %v", err)
	}
	server := &http.Server{
		Addr:    ":443",
		Handler: mux,
		TLSConfig: &tls.Config{
			// Only hosts starting with "matls-" require mTLS.
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				log.Printf("picking tls config for %s\n", hello.ServerName)
				cfg := &tls.Config{
					Certificates: []tls.Certificate{serverCert},
					ClientAuth:   tls.NoClientCert,
					MinVersion:   tls.VersionTLS12,
				}
				if strings.HasPrefix(hello.ServerName, "matls-") {
					log.Println("mtls is required")
					cfg.ClientAuth = tls.RequireAndVerifyClientCert
					cfg.ClientCAs = caPool
				}
				return cfg, nil
			},
		},
	}
	if err := server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

// reverseProxyWithFallback is a helper function that creates a reverse proxy
// with a fallback mechanism. It handles TLS connections, client certificates,
// and request body buffering. If the reverse proxy encounters a connection
// refused error, it will serve the request from the fallback proxy.
func reverseProxyWithFallback(reverseProxy, fallbackProxy *httputil.ReverseProxy) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			log.Println("No TLS connection established")
		} else if len(r.TLS.PeerCertificates) == 0 {
			log.Println("TLS established but no client certificate presented")
		} else {
			log.Println("Client certificate received:", r.TLS.PeerCertificates[0].Subject)
		}

		// Extract client certificate if available.
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			log.Println("client certificate found, forwarding it")
			clientCert := r.TLS.PeerCertificates[0]
			pemBytes := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: clientCert.Raw,
			})

			r.Header.Set("X-Client-Cert", url.QueryEscape(string(pemBytes)))
		}

		// Buffer the request body.
		var bodyBytes []byte
		if r.Body != nil {
			bodyBytes, _ = io.ReadAll(r.Body)
		}
		r.Body.Close()

		reverseProxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			log.Println("Proxy error:", err)
			if strings.Contains(err.Error(), "connection refused") {
				log.Println("Connection refused, serving fallback")
				r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
				fallbackProxy.ServeHTTP(w, r)
				return
			}

			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		}

		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		reverseProxy.ServeHTTP(w, r)
	}

}
