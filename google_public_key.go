package secure_backend

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/xerrors"
	"io/ioutil"
	"net/http"
)

type googlePublicKey struct {
	kid       string
	publicKey *rsa.PublicKey
}

func getGooglePublicKeys(url string) ([]*googlePublicKey, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, xerrors.Errorf("Google public key download failed / %v: %w", url, err)
	} else if resp.Body != nil {
		defer func() {
			_ = resp.Body.Close()
		}()
	}

	if resp.StatusCode != http.StatusOK {
		return nil, xerrors.Errorf("Google public key download status error: %v / %v", resp.StatusCode, url)
	}

	metadataBody, err := ioutil.ReadAll(resp.Body)
	keys := map[string]string{}

	err = json.Unmarshal(metadataBody, &keys)
	if err != nil {
		return nil, xerrors.Errorf("Google public key parse failed: %w", err)
	}

	resultKeys := make([]*googlePublicKey, 0)
	for kid, pemString := range keys {
		key, err := parseGooglePublicKey(kid, pemString)
		if err != nil {
			return nil, xerrors.Errorf("Google public key(%v) decode failed: %w", kid, err)
		}

		resultKeys = append(resultKeys, key)
	}

	return resultKeys, nil
}

func parseGooglePublicKey(kid string, key string) (*googlePublicKey, error) {
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return nil, errors.New(fmt.Sprintf("PEM decode failed(%v)", kid))
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, xerrors.Errorf("ParseCertificate failed(%v): %w", kid, err)
	}
	pk, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New(fmt.Sprintf("is not public key(%v)", kid))
	}
	return &googlePublicKey{kid, pk}, nil
}
