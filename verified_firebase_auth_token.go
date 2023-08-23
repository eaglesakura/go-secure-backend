package secure_backend

import (
	"errors"
	"fmt"
	"time"
)

/*
Verified JWT Data.
*/
type VerifiedFirebaseAuthToken struct {
	/*
		Authorize user.
	*/
	User *FirebaseUser

	/*
		Token expire time.
	*/
	ExpireAt time.Time

	/*
		JWT Claims.
	*/
	Claims map[string]interface{}
}

func (it *VerifiedFirebaseAuthToken) GetIntClaim(key string) (int64, error) {
	v, ok := it.Claims[key]
	if !ok {
		return 0, errors.New(fmt.Sprintf("claim key not found[%v]", key))
	}

	switch v.(type) {
	case int64:
		return v.(int64), nil
	case int:
		return int64(v.(int)), nil
	case float64:
		return int64(v.(float64)), nil
	}

	return 0, errors.New(fmt.Sprintf("claim type error[%v]", key))
}

func (it *VerifiedFirebaseAuthToken) GetStringClaim(key string) (string, error) {
	v, ok := it.Claims[key]
	if !ok {
		return "", errors.New(fmt.Sprintf("claim key not found[%v]", key))
	}
	return fmt.Sprintf("%v", v), nil
}

func (it *VerifiedFirebaseAuthToken) GetFloatClaim(key string) (float64, error) {
	v, ok := it.Claims[key]
	if !ok {
		return 0, errors.New(fmt.Sprintf("claim key not found[%v]", key))
	}

	switch v.(type) {
	case int64:
		return float64(v.(int64)), nil
	case int:
		return float64(v.(int)), nil
	case float64:
		return v.(float64), nil
	}

	return 0, errors.New(fmt.Sprintf("claim type error[%v]", key))
}
