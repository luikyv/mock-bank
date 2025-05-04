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

	mux.HandleFunc("GET directory/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		http.ServeFile(w, r, "/mocks/directory_well_known.json")
	})

	mux.HandleFunc("GET directory/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		var jwks jose.JSONWebKeySet
		for _, key := range directoryJWKS.Keys {
			jwks.Keys = append(jwks.Keys, key.Public())
		}
		_ = json.NewEncoder(w).Encode(jwks)
	})

	mux.HandleFunc("POST directory/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{
			"access_token": "random_token",
			"token_type": "bearer"
		}`)
	})

	mux.HandleFunc("GET directory/authorize", func(w http.ResponseWriter, r *http.Request) {
		key := directoryJWKS.Keys[0]
		joseSigner, _ := jose.NewSigner(jose.SigningKey{
			Algorithm: jose.SignatureAlgorithm(key.Algorithm),
			Key:       key,
		}, (&jose.SignerOptions{}).WithType("JWT"))

		idToken, _ := jwt.Signed(joseSigner).Claims(idTokenClaims).Serialize()

		http.Redirect(w, r, fmt.Sprintf("https://api.mockbank.local/app/directory/callback?id_token=%s", idToken), http.StatusSeeOther)
	})

	mux.HandleFunc("GET directory/participants", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		http.ServeFile(w, r, "/mocks/participants.json")
	})

	mux.HandleFunc("GET directory/organisations/{org_id}/softwarestatements/{ss_id}/assertion", func(w http.ResponseWriter, r *http.Request) {
		key := directoryJWKS.Keys[0]
		joseSigner, _ := jose.NewSigner(jose.SigningKey{
			Algorithm: jose.SignatureAlgorithm(key.Algorithm),
			Key:       key,
		}, (&jose.SignerOptions{}).WithType("JWT"))

		ssa, _ := jwt.Signed(joseSigner).Claims(ssClaims).Serialize()

		w.Header().Set("Content-Type", "application/jwt")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, ssa)
	})

	mux.HandleFunc("GET keystore/{org_id}/application.jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		http.ServeFile(w, r, "/mocks/client.jwks")
	})

	appURL, _ := url.Parse("http://host.docker.internal:8080")
	mux.Handle("app.mockbank.local/", httputil.NewSingleHostReverseProxy(appURL))

	// Reverse proxy fallback.
	fallbackURL, _ := url.Parse("http://host.docker.internal")
	fallbackProxy := httputil.NewSingleHostReverseProxy(fallbackURL)
	// Reverse proxy for mockbank.
	mockbankURL, _ := url.Parse("http://mockbank")
	reverseProxy := httputil.NewSingleHostReverseProxy(mockbankURL)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Extract client certificate if available.
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
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
	})

	// Serve participant information over HTTP because the Conformance Suite
	// does not accept self-signed certificates.
	http.HandleFunc("GET directory/participants", func(w http.ResponseWriter, r *http.Request) {
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
	server := &http.Server{
		Addr:    ":443",
		Handler: mux,
		TLSConfig: &tls.Config{
			ClientCAs:  clientCAPool,
			ClientAuth: tls.VerifyClientCertIfGiven,
		},
	}
	if err := server.ListenAndServeTLS("/mocks/server.crt", "/mocks/server.key"); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
