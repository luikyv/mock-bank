package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
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

	directoryJWKSBytes, err := os.ReadFile("/mocks/directory_jwks.json")
	if err != nil {
		log.Fatal("failed to read directory jwks:", err)
	}
	var directoryJWKS jose.JSONWebKeySet
	if err := json.Unmarshal(directoryJWKSBytes, &directoryJWKS); err != nil {
		log.Fatal("failed to parse directory jwks:", err)
	}

	keystoreJWKSBytes, err := os.ReadFile("/mocks/keystore_jwks.json")
	if err != nil {
		log.Fatal("failed to read keystore jwks:", err)
	}
	var keystoreJWKS jose.JSONWebKeySet
	if err := json.Unmarshal(keystoreJWKSBytes, &keystoreJWKS); err != nil {
		log.Fatal("failed to parse keystore jwks:", err)
	}

	idTokenBytes, err := os.ReadFile("/mocks/id_token.json")
	if err != nil {
		log.Fatal("failed to read id token:", err)
	}
	var idTokenClaims map[string]any
	_ = json.Unmarshal(idTokenBytes, &idTokenClaims)

	ssBytes, err := os.ReadFile("/mocks/software_statement.json")
	if err != nil {
		log.Fatal("failed to read id token:", err)
	}
	var ssClaims map[string]any
	_ = json.Unmarshal(ssBytes, &ssClaims)

	mux := http.NewServeMux()

	mux.HandleFunc("GET directory.local/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Request directory openid configuration")
		w.Header().Set("Content-Type", "application/json")
		http.ServeFile(w, r, "/mocks/directory_well_known.json")
	})

	mux.HandleFunc("GET directory.local/jwks", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Request directory jwks")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		var jwks jose.JSONWebKeySet
		for _, key := range directoryJWKS.Keys {
			jwks.Keys = append(jwks.Keys, key.Public())
		}
		_ = json.NewEncoder(w).Encode(jwks)
	})

	mux.HandleFunc("POST directory.local/token", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Request directory token")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{
			"access_token": "random_token",
			"token_type": "bearer"
		}`)
	})

	mux.HandleFunc("GET directory.local/authorize", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Request directory authorize")
		key := directoryJWKS.Keys[0]
		joseSigner, _ := jose.NewSigner(jose.SigningKey{
			Algorithm: jose.SignatureAlgorithm(key.Algorithm),
			Key:       key,
		}, (&jose.SignerOptions{}).WithType("JWT"))

		idToken, _ := jwt.Signed(joseSigner).Claims(idTokenClaims).Serialize()

		http.Redirect(w, r, fmt.Sprintf("https://app.mockbank.local/api/directory/callback?id_token=%s", idToken), http.StatusSeeOther)
	})

	mux.HandleFunc("GET directory.local/participants", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Request directory participants")
		w.Header().Set("Content-Type", "application/json")
		http.ServeFile(w, r, "/mocks/participants.json")
	})

	mux.HandleFunc("GET directory.local/organisations/{org_id}/softwarestatements/{ss_id}/assertion", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Request directory software statement")
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

	mux.HandleFunc("GET keystore.local/{org_id}/{software_id}/application.jwks", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Request keystore client jwks")
		w.Header().Set("Content-Type", "application/json")
		http.ServeFile(w, r, "/mocks/client.jwks")
	})

	mux.HandleFunc("GET keystore.local/", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Request keystore jwks")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		var jwks jose.JSONWebKeySet
		for _, key := range keystoreJWKS.Keys {
			jwks.Keys = append(jwks.Keys, key.Public())
		}
		_ = json.NewEncoder(w).Encode(jwks)
	})

	// Reverse proxy fallback.
	fallbackURL, _ := url.Parse("http://host.docker.internal")
	fallbackProxy := httputil.NewSingleHostReverseProxy(fallbackURL)
	// Reverse proxy for mockbank.
	mockbankURL, _ := url.Parse("http://mockbank")
	reverseProxy := httputil.NewSingleHostReverseProxy(mockbankURL)
	mbHandler := mockbankHandler(reverseProxy, fallbackProxy)
	mux.HandleFunc("auth.mockbank.local/", mbHandler)
	mux.HandleFunc("matls-auth.mockbank.local/", mbHandler)
	mux.HandleFunc("matls-api.mockbank.local/", mbHandler)
	mux.HandleFunc("app.mockbank.local/api/", mbHandler)

	appURL, _ := url.Parse("http://host.docker.internal:8080")
	mux.Handle("app.mockbank.local/", httputil.NewSingleHostReverseProxy(appURL))

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

	caCertPEM, err := os.ReadFile("/mocks/client_ca.crt")
	if err != nil {
		log.Fatal("Failed to read client CA file:", err)
	}
	clientCAPool := x509.NewCertPool()
	if ok := clientCAPool.AppendCertsFromPEM(caCertPEM); !ok {
		log.Fatal("Failed to append client CA certs")
	}
	serverCert, err := tls.LoadX509KeyPair("/mocks/server.crt", "/mocks/server.key")
	if err != nil {
		log.Fatalf("failed to load server certificate: %v", err)
	}
	server := &http.Server{
		Addr:    ":443",
		Handler: mux,
		TLSConfig: &tls.Config{
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
					cfg.ClientCAs = clientCAPool
				}
				return cfg, nil
			},
		},
	}
	if err := server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func mockbankHandler(reverseProxy, fallbackProxy *httputil.ReverseProxy) http.HandlerFunc {
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

		// Replace with a new ReadCloser for ReverseProxy.
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		// Make a copy of the request in case fallback is needed.
		rCopy := r.Clone(r.Context())
		rCopy.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		reverseProxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			log.Println("Proxy error:", err)
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) {
				log.Println("DNS resolution failed, serving fallback")
				fallbackProxy.ServeHTTP(w, rCopy)
				return
			}
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		}

		reverseProxy.ServeHTTP(w, r)
	}

}
