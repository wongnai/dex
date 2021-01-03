package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dexidp/dex/pkg/log"
	"github.com/dexidp/dex/signer"
	vault "github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
	"gopkg.in/square/go-jose.v2"
	"hash"
	"strconv"
	"strings"
	"sync"
)

type Signer struct {
	vault  *vault.Client
	config Config
	logger log.Logger

	keyAlgo     string
	keyAlgoOnce sync.Once
}

func (s *Signer) getKeyAlgo() string {
	s.keyAlgoOnce.Do(func() {
		s.logger.Info("vault: getting key info")
		info, err := s.getKeyInfo()
		if err != nil {
			s.logger.Info("vault: fail to fetch key info")
			panic(err)
		}
		s.keyAlgo = info.Type
	})
	return s.keyAlgo
}

func (s *Signer) getKeyInfo() (keyInfo, error) {
	data, err := s.vault.Logical().Read(fmt.Sprintf("%s/keys/%s", s.config.TransitMount, s.config.KeyName))
	var info keyInfo
	if err = mapstructure.Decode(data.Data, &info); err != nil {
		return keyInfo{}, err
	}

	return info, nil
}

func (s *Signer) Hasher() (hash.Hash, error) {
	return signer.HashForSigAlgorithm(sigAlgoMapping[s.getKeyAlgo()])
}

func (s *Signer) GetSigningKeys() (signer.SigningKeyResponse, error) {
	keys, err := s.getKeyInfo()
	if err != nil {
		return signer.SigningKeyResponse{}, err
	}
	jwks, err := s.keyInfoToJwks(keys)
	if err != nil {
		return signer.SigningKeyResponse{}, err
	}

	return signer.SigningKeyResponse{
		Jwks: jwks,
	}, nil
}

func (s *Signer) Sign(payload []byte) (string, error) {
	info, err := s.getKeyInfo()
	if err != nil {
		return "", err
	}
	algo := info.Type
	latestKeyVersion := info.LatestVersion()

	header := map[jose.HeaderKey]string{
		"alg": string(sigAlgoMapping[algo]),
		"kid": strconv.Itoa(latestKeyVersion),
	}
	headerJson, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	signedPayloadBuf, err := s.buildSignedPayload(headerJson, payload)
	if err != nil {
		return "", err
	}

	hasher, err := s.Hasher()
	if err != nil {
		return "", err
	}
	hasher.Write(signedPayloadBuf)

	var hashedPayload []byte
	hashedPayload = hasher.Sum(hashedPayload)

	b64Hash := base64.StdEncoding.EncodeToString(hashedPayload)

	res, err := s.vault.Logical().Write(fmt.Sprintf("%s/sign/%s", s.config.TransitMount, s.config.KeyName), map[string]interface{}{
		"hash_algorithm":       sigHashMapping[algo],
		"input":                b64Hash,
		"prehashed":            "true",
		"signature_algorithm":  "pkcs1v15",
		"marshaling_algorithm": "jws",
		"key_version":          latestKeyVersion,
	})
	if err != nil {
		return "", err
	}

	sig, ok := res.Data["signature"].(string)
	if !ok {
		return "", errors.New("no signature returned from vault")
	}
	sigParts := strings.SplitN(sig, ":", 3)

	return string(signedPayloadBuf) + "." + sigParts[2], nil
}

func (s *Signer) buildSignedPayload(header []byte, payload []byte) ([]byte, error) {
	signedPayloadBuf := bytes.Buffer{}

	b64encoder := base64.NewEncoder(base64.RawURLEncoding, &signedPayloadBuf)
	b64encoder.Write(header)
	b64encoder.Close()

	signedPayloadBuf.WriteRune('.')

	b64encoder = base64.NewEncoder(base64.RawURLEncoding, &signedPayloadBuf)
	b64encoder.Write(payload)
	b64encoder.Close()

	return signedPayloadBuf.Bytes(), nil
}
