package secure_backend

import (
	"context"
	"testing"

	"github.com/eaglesakura/go-secure-backend/testutils"
	"github.com/stretchr/testify/assert"
)

func TestGoogleApiKeyVerifierImpl_Verify(t *testing.T) {
	owner := &securityContextImpl{}
	ctx := context.Background()
	assert.NoError(t, owner.init(ctx))
	verifier := owner.NewGoogleApiKeyVerifier()

	assert.NoError(t, verifier.Verify(ctx, testutils.GetGoogleApiKeyForTest()))
	// from cache
	assert.NoError(t, verifier.Verify(ctx, testutils.GetGoogleApiKeyForTest()))
}

func TestGoogleApiKeyVerifierImpl_Verify_invalid(t *testing.T) {
	owner := &securityContextImpl{}
	ctx := context.Background()
	assert.NoError(t, owner.init(ctx))
	verifier := owner.NewGoogleApiKeyVerifier()

	assert.Error(t, verifier.Verify(ctx, "this is invalid key"))
}
