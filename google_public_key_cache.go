package secure_backend

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/xerrors"
	"sync"
)

type googlePublicKeyCache struct {
	/*
		Metadata server URL.
	*/
	metadataUrl string
	lock        *sync.Mutex
	latestKey   *googlePublicKey
	offlineKeys map[string]*googlePublicKey
	allKeys     map[string]*googlePublicKey
}

func (it *googlePublicKeyCache) addOfflineKey(key *googlePublicKey) {
	it.offlineKeys[key.kid] = key
	if it.latestKey == nil {
		it.latestKey = key
	}
}

func (it *googlePublicKeyCache) refreshKeys() error {
	it.lock.Lock()
	defer it.lock.Unlock()

	keys, err := getGooglePublicKeys(it.metadataUrl)
	if err != nil {
		return xerrors.Errorf("Public key cache refresh failed: %w", err)
	}

	it.allKeys = make(map[string]*googlePublicKey)
	for _, key := range it.offlineKeys {
		it.allKeys[key.kid] = key
	}
	for _, key := range keys {
		it.allKeys[key.kid] = key
	}

	return nil
}

func (it *googlePublicKeyCache) parseJwt(token string) (*googlePublicKey, *jwt.Token, error) {
	// check latest
	latest := it.latestKey
	if latest != nil {
		if parsed, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			return latest.publicKey, nil
		}); err == nil {
			return latest, parsed, nil
		}
	}

	// Try local cache.
	keys := it.allKeys
	for _, key := range keys {
		parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			return key.publicKey, nil
		})
		if err == nil {
			it.latestKey = key
			return key, parsedToken, nil
		}
	}

	// Not found, refresh
	err := it.refreshKeys()
	if err != nil {
		return nil, nil, err
	} else {
		keys = it.allKeys
	}

	// Try new local cache.
	for _, key := range keys {
		parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			return key.publicKey, nil
		})
		if err == nil {
			it.latestKey = key
			return key, parsedToken, nil
		}
	}

	// Not found public key.
	return nil, nil, errors.New("signature validation failed in all public keys")
}

func newGooglePublicKeyCache(metadataUrl string) *googlePublicKeyCache {
	return &googlePublicKeyCache{
		metadataUrl: metadataUrl,
		lock:        new(sync.Mutex),
		offlineKeys: make(map[string]*googlePublicKey),
	}
}
