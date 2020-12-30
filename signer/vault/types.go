package vault

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"gopkg.in/square/go-jose.v2"
	"strconv"
)

type keyInfo struct {
	Type     string                    `mapstructure:"type"`
	Versions map[string]keyVersionInfo `mapstructure:"keys"`
}

func (k *keyInfo) LatestVersion() int {
	var latestVersion int64 = -1
	for v, _ := range k.Versions {
		version, err := strconv.ParseInt(v, 10, 32)
		if err != nil {
			continue
		}

		if version > latestVersion {
			latestVersion = version
		}
	}

	return int(latestVersion)
}

type keyVersionInfo struct {
	CreationTime string `mapstructure:"creation_time"`
	Name         string `mapstructure:"name"`
	PublicKey    string `mapstructure:"public_key"`
}

func (k keyVersionInfo) GetPublicKeyEd25519() (ed25519.PublicKey, error) {
	return base64.StdEncoding.DecodeString(k.PublicKey)
}

func (k keyVersionInfo) GetPublicKeyPkix() (interface{}, error) {
	block, _ := pem.Decode([]byte(k.PublicKey))
	return x509.ParsePKIXPublicKey(block.Bytes)
}

// sigAlgoMapping contains mapping from Vault key types (https://www.vaultproject.io/docs/secrets/transit#key-types)
// to jose.SignatureAlgorithm
var sigAlgoMapping = map[string]jose.SignatureAlgorithm{
	//"ed25519":    jose.EdDSA,
	"ecdsa-p256": jose.ES256,
	"ecdsa-p384": jose.ES384,
	"ecdsa-p521": jose.ES512,
	"rsa-2048":   jose.RS256,
	"rsa-3072":   jose.RS256,
	"rsa-4096":   jose.RS256,
}

// sigHashMapping must match storage.hashForSigAlgo
var sigHashMapping = map[string]string{
	//"ed25519":    "", // omit for vault to pick
	"ecdsa-p256": "sha2-256",
	"ecdsa-p384": "sha2-384",
	"ecdsa-p521": "sha2-512",
	"rsa-2048":   "sha2-256",
	"rsa-3072":   "sha2-384",
	"rsa-4096":   "sha2-512",
}

func (s *Signer) keyInfoToJwks(info keyInfo) (jose.JSONWebKeySet, error) {
	var err error
	algo, ok := sigAlgoMapping[info.Type]
	if !ok {
		return jose.JSONWebKeySet{}, fmt.Errorf("unsupported algorithm %s", info.Type)
	}

	out := jose.JSONWebKeySet{}
	for keyId, value := range info.Versions {
		var pubkey interface{}

		switch info.Type {
		case "ed25519":
			pubkey, err = value.GetPublicKeyEd25519()
		default:
			pubkey, err = value.GetPublicKeyPkix()
		}
		if err != nil {
			s.logger.Warnf("unable to parse key %s: %s", keyId, err.Error())
			continue
		}

		key := jose.JSONWebKey{
			Key:       pubkey,
			KeyID:     keyId,
			Algorithm: string(algo),
			Use:       "sig",
		}
		out.Keys = append(out.Keys, key)
	}

	if len(out.Keys) == 0 {
		return out, errors.New("no keys found")
	}

	return out, nil
}
