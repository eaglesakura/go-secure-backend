package internal

import (
	"github.com/eaglesakura/secure_backend/testutils"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGoogleApiKeyVerifierImpl_Verify(t *testing.T) {
	owner := &securityContextImpl{}
	assert.NoError(t, owner.init())
	verifier := owner.NewGoogleApiKeyVerifier()

	assert.NoError(t, verifier.Verify(testutils.GetGoogleApiKeyForTest()))
	// from cache
	assert.NoError(t, verifier.Verify(testutils.GetGoogleApiKeyForTest()))
}

func TestGoogleApiKeyVerifierImpl_Verify_invalid(t *testing.T) {
	owner := &securityContextImpl{}
	assert.NoError(t, owner.init())
	verifier := owner.NewGoogleApiKeyVerifier()

	assert.Error(t, verifier.Verify("this is invalid key"))
}
