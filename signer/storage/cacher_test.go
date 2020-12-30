package storage

import (
	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/memory"
	"github.com/sirupsen/logrus"
	"os"
	"testing"
	"time"
)

var logger = &logrus.Logger{
	Out:       os.Stderr,
	Formatter: &logrus.TextFormatter{DisableColors: true},
	Level:     logrus.DebugLevel,
}

type storageWithKeysTrigger struct {
	storage.Storage
	f func()
}

func (s storageWithKeysTrigger) GetKeys() (storage.Keys, error) {
	s.f()
	return s.Storage.GetKeys()
}

func TestKeyCacher(t *testing.T) {
	tNow := time.Now()
	now := func() time.Time { return tNow }

	s := memory.New(logger)

	tests := []struct {
		before            func()
		wantCallToStorage bool
	}{
		{
			before:            func() {},
			wantCallToStorage: true,
		},
		{
			before: func() {
				s.UpdateKeys(func(old storage.Keys) (storage.Keys, error) {
					old.NextRotation = tNow.Add(time.Minute)
					return old, nil
				})
			},
			wantCallToStorage: true,
		},
		{
			before:            func() {},
			wantCallToStorage: false,
		},
		{
			before: func() {
				tNow = tNow.Add(time.Hour)
			},
			wantCallToStorage: true,
		},
		{
			before: func() {
				tNow = tNow.Add(time.Hour)
				s.UpdateKeys(func(old storage.Keys) (storage.Keys, error) {
					old.NextRotation = tNow.Add(time.Minute)
					return old, nil
				})
			},
			wantCallToStorage: true,
		},
		{
			before:            func() {},
			wantCallToStorage: false,
		},
	}

	gotCall := false
	s = newKeyCacher(storageWithKeysTrigger{s, func() { gotCall = true }}, now)
	for i, tc := range tests {
		gotCall = false
		tc.before()
		s.GetKeys()
		if gotCall != tc.wantCallToStorage {
			t.Errorf("case %d: expected call to storage=%t got call to storage=%t", i, tc.wantCallToStorage, gotCall)
		}
	}
}
