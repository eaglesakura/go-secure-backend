package secure_backend

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_securityContextImpl_init(t *testing.T) {
	impl := &securityContextImpl{}

	err := impl.init()
	assert.NoError(t, err)
	assert.NotNil(t, impl.ctx)

	// check gcp
	assert.NotEmpty(t, impl.gcp.serviceAccountJson)
	assert.NotNil(t, impl.gcp.firebaseAuth)
	assert.NotNil(t, impl.gcp.serviceControlClient)
	assert.NotEmpty(t, impl.gcp.clientEmail)
	assert.NotNil(t, impl.gcp.privateKey)
	assert.NotEmpty(t, impl.gcp.projectId)
}
