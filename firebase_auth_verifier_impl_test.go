package secure_backend

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

//func TestGetGooglePublicKey(t *testing.T) {
//	service, err := iam.NewService(context.Background())
//	assert.NoError(t, err)
//	assert.NotNil(t, service)
//
//	credentials, err := google.FindDefaultCredentials(context.Background())
//	assert.NoError(t, err)
//	assert.NotNil(t, credentials)
//}

func TestFirebaseAuthVerifierImpl_Verify(t *testing.T) {
	owner := &securityContextImpl{}
	assert.NoError(t, owner.init())
	verifier := owner.NewFirebaseAuthVerifier().AcceptOriginalToken()

	customToken, _ := owner.gcp.firebaseAuth.CustomTokenWithClaims(owner.ctx, "custom-token-user", map[string]interface{}{
		"foo":       "bar",
		"hoge":      "fuga",
		"int_claim": 123,
	})

	parsed, err := verifier.Verify(customToken)
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
	assert.NoError(t, owner.init())
	verifier := owner.NewFirebaseAuthVerifier().AcceptOriginalToken()

	customToken, _ := owner.gcp.firebaseAuth.CustomTokenWithClaims(owner.ctx, "custom-token-user", map[string]interface{}{
		"foo":  "bar",
		"hoge": "fuga",
	})
	customToken += "broken" // signature bloken!!

	parsed, err := verifier.Verify(customToken)
	assert.Error(t, err)
	assert.Nil(t, parsed)
}

func TestFirebaseAuthVerifierImpl_Verify_broken_sign2(t *testing.T) {
	owner := &securityContextImpl{}
	assert.NoError(t, owner.init())
	verifier := owner.NewFirebaseAuthVerifier().AcceptOriginalToken()

	customToken, _ := owner.gcp.firebaseAuth.CustomTokenWithClaims(owner.ctx, "custom-token-user", map[string]interface{}{
		"foo":  "bar",
		"hoge": "fuga",
	})
	customToken += " " // signature bloken!!

	parsed, err := verifier.Verify(customToken)
	assert.Error(t, err)
	assert.Nil(t, parsed)
}

func TestFirebaseAuthVerifierImpl_Verify_nosign(t *testing.T) {
	owner := &securityContextImpl{}
	assert.NoError(t, owner.init())
	verifier := owner.NewFirebaseAuthVerifier().AcceptOriginalToken()

	customToken, _ := owner.gcp.firebaseAuth.CustomTokenWithClaims(owner.ctx, "custom-token-user", map[string]interface{}{
		"foo":  "bar",
		"hoge": "fuga",
	})
	split := strings.Split(customToken, ".")

	parsed, err := verifier.Verify(split[0] + "." + split[1])
	assert.Error(t, err)
	assert.Nil(t, parsed)
}

func TestFirebaseAuthVerifierImpl_Verify_without_original(t *testing.T) {
	owner := &securityContextImpl{}
	assert.NoError(t, owner.init())
	verifier := owner.NewFirebaseAuthVerifier()

	customToken, _ := owner.gcp.firebaseAuth.CustomTokenWithClaims(owner.ctx, "custom-token-user", map[string]interface{}{
		"foo":  "bar",
		"hoge": "fuga",
	})
	parsed, err := verifier.Verify(customToken)
	assert.Error(t, err)
	assert.Nil(t, parsed)
}
