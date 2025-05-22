package joseutil

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	"slices"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

var _ crypto.Signer = &KMSSigner{}

type KMSSigner struct {
	client   *kms.Client
	keyID    string
	pubKey   *rsa.PublicKey
	hashFunc crypto.Hash
}

func NewKMSSigner(ctx context.Context, keyID string, kmsClient *kms.Client) (*KMSSigner, error) {
	pubOut, err := kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: &keyID,
	})
	if err != nil {
		return nil, fmt.Errorf("get public key: %w", err)
	}

	pubParsed, err := x509.ParsePKIXPublicKey(pubOut.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	rsaPubKey, ok := pubParsed.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an rsa public key")
	}

	if !slices.Contains(pubOut.SigningAlgorithms, types.SigningAlgorithmSpecRsassaPssSha256) {
		return nil, errors.New("KMS key does not support RSASSA_PSS_SHA_256")
	}

	return &KMSSigner{
		client:   kmsClient,
		keyID:    keyID,
		pubKey:   rsaPubKey,
		hashFunc: crypto.SHA256,
	}, nil
}

func (s *KMSSigner) Public() crypto.PublicKey {
	return s.pubKey
}

func (s *KMSSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != s.hashFunc {
		return nil, fmt.Errorf("unsupported hash function: got %v, want %v", opts.HashFunc(), s.hashFunc)
	}

	out, err := s.client.Sign(context.Background(), &kms.SignInput{
		KeyId:            &s.keyID,
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPssSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("error signing with kms: %w", err)
	}

	return out.Signature, nil
}
