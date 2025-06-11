package jwtutil

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func Sign(claims any, signer crypto.Signer) (string, error) {
	key := jose.SigningKey{
		Algorithm: jose.PS256,
		Key: OpaqueSigner{
			ID:     "signer",
			Signer: signer,
		},
	}
	opts := (&jose.SignerOptions{}).WithType("JWT")

	joseSigner, err := jose.NewSigner(key, opts)
	if err != nil {
		return "", err
	}

	jws, err := jwt.Signed(joseSigner).Claims(claims).Serialize()
	if err != nil {
		return "", err
	}

	return jws, nil
}

var _ jose.OpaqueSigner = OpaqueSigner{}

type OpaqueSigner struct {
	ID     string
	Signer crypto.Signer
}

func (s OpaqueSigner) Public() *jose.JSONWebKey {
	return &jose.JSONWebKey{
		KeyID:     s.ID,
		Key:       s.Signer.Public(),
		Algorithm: string(jose.PS256),
		Use:       "sig",
	}
}

func (s OpaqueSigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{jose.PS256}
}

func (s OpaqueSigner) SignPayload(payload []byte, _ jose.SignatureAlgorithm) ([]byte, error) {
	hasher := crypto.SHA256.New()
	hasher.Write(payload)
	digest := hasher.Sum(nil)

	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}
	return s.Signer.Sign(rand.Reader, digest, opts)
}
