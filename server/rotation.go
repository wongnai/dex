package server

import (
	"context"
	"github.com/dexidp/dex/signer"
	"time"
)

// startKeyRotation begins key rotation in a new goroutine, closing once the context is canceled.
//
// The method blocks until after the first attempt to rotate keys has completed. That way
// healthy storages will return from this call with valid keys.
func (s *Server) startKeyRotation(ctx context.Context) {
	// Try to rotate immediately so properly configured storages will have keys.
	if err := s.signer.RotateKey(); err != nil {
		if err == signer.ErrRotationNotSupported {
			return
		} else if err == signer.ErrAlreadyRotated {
			s.logger.Infof("Key rotation not needed: %v", err)
		} else {
			s.logger.Errorf("failed to rotate keys: %v", err)
		}
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second * 30):
				if err := s.signer.RotateKey(); err != nil {
					s.logger.Errorf("failed to rotate keys: %v", err)
				}
			}
		}
	}()
}
