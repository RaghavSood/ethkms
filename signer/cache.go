package signer

import (
	"crypto/ecdsa"
	"sync"
)

var keyCache = newPubKeyCache()

type pubKeyCache struct {
	pubKeys map[string]*ecdsa.PublicKey
	mutex   sync.RWMutex
}

func newPubKeyCache() *pubKeyCache {
	return &pubKeyCache{
		pubKeys: make(map[string]*ecdsa.PublicKey),
	}
}

func (c *pubKeyCache) Add(keyID string, key *ecdsa.PublicKey) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.pubKeys[keyID] = key
}

func (c *pubKeyCache) Get(keyID string) *ecdsa.PublicKey {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.pubKeys[keyID]
}
