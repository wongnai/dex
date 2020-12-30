package signer

import (
	"gopkg.in/square/go-jose.v2"
	"hash"
	"time"
)

type Signer interface {
	GetSigningKeys() (SigningKeyResponse, error)

	Sign(payload []byte) (jws string, err error)

	// Hasher return new instance of hash.Hash used to sign access token
	Hasher() (hash.Hash, error)
}

type SigningKeyResponse struct {
	Jwks         jose.JSONWebKeySet
	NextRotation *time.Time
}
