package vault

import (
	"github.com/dexidp/dex/pkg/log"
	"github.com/dexidp/dex/signer"
	vault "github.com/hashicorp/vault/api"
)

type Config struct {
	Address string `json:"address" yaml:"address""`
	// TransitMount is the path to transit storage engine
	TransitMount string `json:"mount" yaml:"mount"`
	KeyName      string `json:"key" yaml:"key"`
}

func (c Config) Open(logger log.Logger) (signer.Signer, error) {
	client, err := vault.NewClient(&vault.Config{
		AgentAddress: c.Address,
	})
	if err != nil {
		return nil, err
	}
	out := &Signer{
		vault:  client,
		config: c,
		logger: logger,
	}
	out.getKeyAlgo()

	return out, nil
}
