package secure_backend

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFirebaseAuthVerifierImpl_Verify(t *testing.T) {
	owner := &securityContextImpl{}
	ctx := context.Background()
	assert.NoError(t, owner.init(ctx))
	verifier := owner.NewFirebaseAuthVerifier()
	verifier.AcceptOriginalToken()

	customToken, _ := owner.gcp.firebaseAuth.CustomTokenWithClaims(ctx, "custom-token-user", map[string]interface{}{
		"foo":       "bar",
		"hoge":      "fuga",
		"int_claim": 123,
	})

	parsed, err := verifier.Verify(ctx, customToken)
	assert.NoError(t, err)
	assert.NotNil(t, parsed)
	assert.Equal(t, "custom-token-user", parsed.User.Id)
	assert.Equal(t, "bar", parsed.Claims["foo"])
	assert.Equal(t, "fuga", parsed.Claims["hoge"])

	foo, err := parsed.GetStringClaim("foo")
	assert.NoError(t, err)
	assert.Equal(t, "bar", foo)

	hoge, err := parsed.GetStringClaim("hoge")
	assert.NoError(t, err)
	assert.Equal(t, "fuga", hoge)

	intClaim, err := parsed.GetIntClaim("int_claim")
	assert.NoError(t, err)
	assert.Equal(t, int64(123), intClaim)
}

func TestFirebaseAuthVerifierImpl_Verify_broken_sign(t *testing.T) {
	owner := &securityContextImpl{}
	ctx := context.Background()
	assert.NoError(t, owner.init(ctx))
	verifier := owner.NewFirebaseAuthVerifier()
	verifier.AcceptOriginalToken()

	customToken, _ := owner.gcp.firebaseAuth.CustomTokenWithClaims(ctx, "custom-token-user", map[string]interface{}{
		"foo":  "bar",
		"hoge": "fuga",
	})
	customToken += "broken" // signature bloken!!

	parsed, err := verifier.Verify(ctx, customToken)
	assert.Error(t, err)
	assert.Nil(t, parsed)
}

func TestFirebaseAuthVerifierImpl_Verify_broken_sign2(t *testing.T) {
	owner := &securityContextImpl{}
	ctx := context.Background()
	assert.NoError(t, owner.init(ctx))
	verifier := owner.NewFirebaseAuthVerifier()
	verifier.AcceptOriginalToken()

	customToken, _ := owner.gcp.firebaseAuth.CustomTokenWithClaims(ctx, "custom-token-user", map[string]interface{}{
		"foo":  "bar",
		"hoge": "fuga",
	})
	customToken += " " // signature bloken!!

	parsed, err := verifier.Verify(ctx, customToken)
	assert.Error(t, err)
	assert.Nil(t, parsed)
}

func TestFirebaseAuthVerifierImpl_Verify_nosign(t *testing.T) {
	owner := &securityContextImpl{}
	ctx := context.Background()
	assert.NoError(t, owner.init(ctx))
	verifier := owner.NewFirebaseAuthVerifier()
	verifier.AcceptOriginalToken()

	customToken, _ := owner.gcp.firebaseAuth.CustomTokenWithClaims(ctx, "custom-token-user", map[string]interface{}{
		"foo":  "bar",
		"hoge": "fuga",
	})
	split := strings.Split(customToken, ".")

	parsed, err := verifier.Verify(ctx, split[0]+"."+split[1])
	assert.Error(t, err)
	assert.Nil(t, parsed)
}

func TestFirebaseAuthVerifierImpl_Verify_without_original(t *testing.T) {
	owner := &securityContextImpl{}
	ctx := context.Background()
	assert.NoError(t, owner.init(ctx))
	verifier := owner.NewFirebaseAuthVerifier()

	customToken, _ := owner.gcp.firebaseAuth.CustomTokenWithClaims(ctx, "custom-token-user", map[string]interface{}{
		"foo":  "bar",
		"hoge": "fuga",
	})
	parsed, err := verifier.Verify(ctx, customToken)
	assert.Error(t, err)
	assert.Nil(t, parsed)
}
