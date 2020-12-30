package storage

import (
	"github.com/dexidp/dex/pkg/log"
	"github.com/dexidp/dex/signer"
	"github.com/dexidp/dex/storage"
	"time"
)

type Config struct {
	Storage storage.Storage
	Now     func() time.Time
}

func (c *Config) Open(logger log.Logger) (signer.Signer, error) {
	now := c.Now
	if now == nil {
		now = time.Now
	}

	return &Signer{
		storage: newKeyCacher(c.Storage, now),
		logger:  logger,
	}, nil
}
