package storage

import (
	"errors"
	"fmt"
	"github.com/dexidp/dex/pkg/log"
	"github.com/dexidp/dex/signer"
	"github.com/dexidp/dex/storage"
	"gopkg.in/square/go-jose.v2"
	"hash"
)

type Signer struct {
	storage storage.Storage
	logger  log.Logger
}

func (s *Signer) GetSigningKeys() (signer.SigningKeyResponse, error) {
	keys, err := s.storage.GetKeys()
	if err != nil {
		return signer.SigningKeyResponse{}, err
	}

	if keys.SigningKeyPub == nil {
		return signer.SigningKeyResponse{}, errors.New("no public keys found")
	}

	jwks := jose.JSONWebKeySet{
		Keys: make([]jose.JSONWebKey, len(keys.VerificationKeys)+1),
	}
	jwks.Keys[0] = *keys.SigningKeyPub
	for i, verificationKey := range keys.VerificationKeys {
		jwks.Keys[i+1] = *verificationKey.PublicKey
	}

	return signer.SigningKeyResponse{
		Jwks:         jwks,
		NextRotation: &keys.NextRotation,
	}, nil
}

func (s *Signer) Hasher() (hash.Hash, error) {
	keys, err := s.storage.GetKeys()
	if err != nil {
		return nil, err
	}
	sigAlgo, err := signer.SignatureAlgorithm(keys.SigningKey)
	if err != nil {
		return nil, err
	}
	return signer.HashForSigAlgorithm(sigAlgo)
}

func (s *Signer) Sign(payload []byte) (jws string, err error) {
	keys, err := s.storage.GetKeys()
	if err != nil {
		return "", err
	}
	sigAlgo, err := signer.SignatureAlgorithm(keys.SigningKey)
	if err != nil {
		return "", err
	}

	signingKey := jose.SigningKey{
		Key:       keys.SigningKey,
		Algorithm: sigAlgo,
	}

	signer, err := jose.NewSigner(signingKey, &jose.SignerOptions{})
	if err != nil {
		return "", fmt.Errorf("new signier: %v", err)
	}
	signature, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("signing payload: %v", err)
	}
	return signature.CompactSerialize()
}
