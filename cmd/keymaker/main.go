package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

var (
	oidUID = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}
)

func main() {
	keysDir := flag.String("keys_dir", "", "Keys Folder")
	orgID := flag.String("org_id", uuid.NewString(), "Organization ID")
	softwareID := flag.String("software_id", uuid.NewString(), "Software ID")
	flag.Parse()

	if *keysDir == "" {
		panic("keys_dir is required")
	}

	// Create the "keys" directory if it doesn't exist.
	err := os.MkdirAll(*keysDir, 0o700)
	if err != nil {
		log.Fatalf("Failed to create keys directory: %v", err)
	}

	caCert, caKey := generateCACert("ca", *keysDir)
	// caCert, caKey := loadCACertAndKey(filepath.Join(*keysDir, "ca.crt"), filepath.Join(*keysDir, "ca.key"))

	generateTransportCert("server_transport", *softwareID, *orgID, caCert, caKey, *keysDir)
	serverCert, serverKey := generateServerCert("server", *keysDir)
	generateJWKS("server", serverCert, serverKey, *keysDir)

	orgSigningCert, orgSigningKey := generateSigningCert("org_signing", *softwareID, *orgID, caCert, caKey, *keysDir)
	generateJWKS("org", orgSigningCert, orgSigningKey, *keysDir)

	_, _ = generateSigningCert("op_signing", *softwareID, *orgID, caCert, caKey, *keysDir)

	generateTransportCert("directory_client_transport", *softwareID, *orgID, caCert, caKey, *keysDir)
	_, _ = generateSigningCert("directory_client_signing", *softwareID, *orgID, caCert, caKey, *keysDir)

	generateTransportCert("client_one_transport", *softwareID, *orgID, caCert, caKey, *keysDir)
	clientOneSigningCert, clientOneSigningKey := generateSigningCert("client_one_signing", *softwareID, *orgID, caCert, caKey, *keysDir)
	generateJWKS("client_one", clientOneSigningCert, clientOneSigningKey, *keysDir)

	generateTransportCert("client_two_transport", *softwareID, *orgID, caCert, caKey, *keysDir)
	clientTwoTransportCert, clientTwoTransportKey := generateSigningCert("client_two_signing", *softwareID, *orgID, caCert, caKey, *keysDir)
	generateJWKS("client_two", clientTwoTransportCert, clientTwoTransportKey, *keysDir)
}

func generateServerCert(name, dir string) (*x509.Certificate, *rsa.PrivateKey) {
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: name,
		},
		DNSNames: []string{
			"app.mockbank.local",
			"auth.mockbank.local",
			"matls-auth.mockbank.local",
			"matls-api.mockbank.local",
			"directory.local",
			"keystore.local",
			"keystore.sandbox.directory.openbankingbrasil.org.br",
			"auth.sandbox.directory.openbankingbrasil.org.br",
			"matls-api.sandbox.directory.openbankingbrasil.org.br",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	return generateSelfSignedCert(name, certTemplate, dir)
}

// Generates a Certificate Authority (CA) key and self-signed certificate.
func generateCACert(name, dir string) (*x509.Certificate, *rsa.PrivateKey) {
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: name,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	return generateSelfSignedCert(name, caTemplate, dir)
}

func generateSelfSignedCert(
	name string,
	template *x509.Certificate,
	dir string,
) (
	*x509.Certificate,
	*rsa.PrivateKey,
) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("Failed to generate CA private key: %v", err)
	}

	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&key.PublicKey,
		key,
	)
	if err != nil {
		log.Fatalf("Failed to create CA certificate: %v", err)
	}
	// This is important for when generation the claim "x5c" of the JWK
	// corresponding to this cert.
	template.Raw = certBytes

	savePEMFile(filepath.Join(dir, name+".key"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key))
	savePEMFile(filepath.Join(dir, name+".crt"), "CERTIFICATE", certBytes)

	log.Printf("Generated self signed certificate and key for %s\n", name)
	return template, key
}

func generateTransportCert(
	name, softwareID, orgID string,
	caCert *x509.Certificate, caKey *rsa.PrivateKey,
	dir string,
) (
	*x509.Certificate,
	*rsa.PrivateKey,
) {
	transportKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("Failed to generate transport private key: %v", err)
	}

	transportCertTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:         softwareID,
			OrganizationalUnit: []string{orgID},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  oidUID,
					Value: softwareID,
				},
			},
		},
		NotBefore:   time.Now().Add(-5 * time.Minute),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, transportCertTmpl, caCert, &transportKey.PublicKey, caKey)
	if err != nil {
		log.Fatalf("Failed to create transport certificate: %v", err)
	}

	savePEMFile(filepath.Join(dir, name+".key"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(transportKey))
	savePEMFile(filepath.Join(dir, name+".crt"), "CERTIFICATE", certDER)

	log.Printf("Generated transport key and certificate for %s\n", name)

	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		log.Fatalf("Failed to parse generated certificate: %v", err)
	}

	return parsedCert, transportKey
}

func generateSigningCert(
	name, softwareID, orgID string,
	caCert *x509.Certificate, caKey *rsa.PrivateKey,
	dir string,
) (
	*x509.Certificate,
	*rsa.PrivateKey,
) {
	signingKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("Failed to generate signing private key: %v", err)
	}

	signingCertTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:         softwareID,
			OrganizationalUnit: []string{orgID},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  oidUID,
					Value: softwareID,
				},
			},
		},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(2 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, signingCertTmpl, caCert, &signingKey.PublicKey, caKey)
	if err != nil {
		log.Fatalf("Failed to create signing certificate: %v", err)
	}

	savePEMFile(filepath.Join(dir, name+".key"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(signingKey))
	savePEMFile(filepath.Join(dir, name+".crt"), "CERTIFICATE", certDER)

	log.Printf("Generated signing key and certificate for %s\n", name)

	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		log.Fatalf("Failed to parse generated signing certificate: %v", err)
	}

	return parsedCert, signingKey
}

// Saves data to a PEM file.
func savePEMFile(filename, blockType string, data []byte) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Failed to create %s: %v", filename, err)
	}
	defer file.Close()

	err = pem.Encode(file, &pem.Block{Type: blockType, Bytes: data})
	if err != nil {
		log.Fatalf("Failed to write PEM data to %s: %v", filename, err)
	}
}

func generateJWKS(
	name string,
	cert *x509.Certificate,
	key *rsa.PrivateKey,
	dir string,
) {
	sigJWK := goidc.JSONWebKey{
		Key:          key,
		KeyID:        "signer",
		Algorithm:    string(goidc.PS256),
		Use:          string(goidc.KeyUsageSignature),
		Certificates: []*x509.Certificate{cert},
	}
	hash := sha256.New()
	_, _ = hash.Write(cert.Raw)
	sigJWK.CertificateThumbprintSHA256 = hash.Sum(nil)

	encKey := generateEncryptionJWK()
	jwks := goidc.JSONWebKeySet{
		Keys: []goidc.JSONWebKey{sigJWK, encKey},
	}

	jwksBytes, err := json.MarshalIndent(jwks, "", " ")
	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(dir, name+".jwks"), jwksBytes, 0644)
	if err != nil {
		log.Fatal(err)
	}

	var publicJWKS goidc.JSONWebKeySet
	for _, jwk := range jwks.Keys {
		publicJWKS.Keys = append(publicJWKS.Keys, jwk.Public())
	}

	publicJWKSBytes, err := json.MarshalIndent(publicJWKS, "", " ")
	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(dir, name+"_pub.jwks"), publicJWKSBytes, 0644)
	if err != nil {
		log.Fatal(err)
	}
}

func generateEncryptionJWK() goidc.JSONWebKey {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("Failed to generate RSA private key: %v", err)
	}

	return goidc.JSONWebKey{
		Key:       key,
		KeyID:     "encrypter",
		Algorithm: string(goidc.RSA_OAEP),
		Use:       string(goidc.KeyUsageEncryption),
	}
}

// loadCACertAndKey loads a CA certificate and private key from PEM files.
func loadCACertAndKey(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		log.Fatalf("Failed to load CA cert: %v", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		log.Fatalf("Failed to load CA key: %v", err)
	}

	// Decode cert
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Fatalf("Failed to decode CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse CA cert: %v", err)
	}

	// Decode key
	block, _ = pem.Decode(keyPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		log.Fatalf("Failed to decode CA key: %v", err)
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse CA key: %v", err)
	}

	return cert, key
}
