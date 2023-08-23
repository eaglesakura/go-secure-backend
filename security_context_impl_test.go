package secure_backend

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_securityContextImpl_init(t *testing.T) {
	impl := &securityContextImpl{}
	ctx := context.Background()
	err := impl.init(ctx)
	assert.NoError(t, err)

	// check gcp
	assert.NotEmpty(t, impl.gcp.serviceAccountJson)
	assert.NotNil(t, impl.gcp.firebaseAuth)
	assert.NotNil(t, impl.gcp.serviceControlClient)
	assert.NotEmpty(t, impl.gcp.clientEmail)
	assert.NotNil(t, impl.gcp.serviceAccountPublicKeys)
	assert.NotNil(t, impl.gcp.serviceAccountPublicKeys.latestKey)
	assert.NotEmpty(t, impl.gcp.projectId)
}
