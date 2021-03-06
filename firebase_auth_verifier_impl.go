package secure_backend

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/xerrors"
	"time"
)

type firebaseAuthVerifierImpl struct {
	owner *securityContextImpl

	logger *Logger

	/*
		option.
	*/
	acceptOriginalToken bool
}

func (it *firebaseAuthVerifierImpl) logInfo(msg string) {
	it.logger.logInfo(msg)
}

func (it *firebaseAuthVerifierImpl) logError(msg string) {
	it.logger.logError(msg)
}

func (it *firebaseAuthVerifierImpl) Logger(logger *Logger) FirebaseAuthVerifier {
	it.logger = logger
	return it
}

func (it *firebaseAuthVerifierImpl) AcceptOriginalToken() FirebaseAuthVerifier {
	it.acceptOriginalToken = true
	return it
}

func (it *firebaseAuthVerifierImpl) verifyOriginalToken(token string) (*VerifiedFirebaseAuthToken, error) {
	_, parsed, err := it.owner.gcp.serviceAccountPublicKeys.parseJwt(token)

	if err != nil {
		it.logError(fmt.Sprintf("jwt.Parse error: %v", err))
		return nil, xerrors.Errorf("JWT.parse failed: %w", err)
	} else if !parsed.Valid {
		return nil, errors.New("invalid JWT")
	} else {
		claims := parsed.Claims.(jwt.MapClaims)
		if err := claims.Valid(); err != nil {
			return nil, err
		} else if !claims.VerifyAudience("https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit", true) {
			return nil, errors.New("invalid JWT.aud")
		} else if !claims.VerifyExpiresAt(time.Now().Unix(), true) {
			return nil, errors.New("invalid JWT.exp")
		} else if !claims.VerifyIssuer(it.owner.gcp.clientEmail, true) {
			return nil, errors.New("invalid JWT.iss")
		}

		allClaims := map[string]interface{}{}
		for key, value := range claims {
			if key == "claims" {
				for cKey, cValue := range value.(map[string]interface{}) {
					allClaims[cKey] = cValue
				}
			} else {
				allClaims[key] = value
			}
		}

		if uid, ok := allClaims["uid"]; !ok {
			return nil, errors.New("invalid JWT.uid")
		} else if exp, ok := allClaims["exp"]; !ok {
			return nil, errors.New("invalid JWT.exp")
		} else {
			var expTime time.Time
			switch exp := exp.(type) {
			case float64:
				expTime = time.Unix(int64(exp), 0)
			case json.Number:
				t, _ := exp.Int64()
				expTime = time.Unix(t, 0)
			}

			return &VerifiedFirebaseAuthToken{
				User: &FirebaseUser{
					Id: uid.(string),
				},
				Claims:   allClaims,
				ExpireAt: expTime,
			}, nil
		}
	}
}

func (it *firebaseAuthVerifierImpl) verifyFirebaseClientToken(token string) (*VerifiedFirebaseAuthToken, error) {
	parsed, err := it.owner.gcp.firebaseAuth.VerifyIDToken(it.owner.ctx, token)
	if err != nil {
		return nil, err
	} else {
		allClaims := map[string]interface{}{
			"iss": parsed.Issuer,
			"aud": parsed.Audience,
			"exp": parsed.Expires,
			"iat": parsed.IssuedAt,
			"sub": parsed.Subject,
			"uid": parsed.UID,
		}
		for key, value := range parsed.Claims {
			allClaims[key] = value
		}
		return &VerifiedFirebaseAuthToken{
			User: &FirebaseUser{
				Id: parsed.UID,
			},
			Claims:   allClaims,
			ExpireAt: time.Unix(parsed.Expires, 0),
		}, nil
	}
}

func (it *firebaseAuthVerifierImpl) Verify(token string) (*VerifiedFirebaseAuthToken, error) {
	parse, _ := jwt.Parse(token, nil)
	if parse == nil {
		return nil, errors.New("token parse error")
	}

	claims := parse.Claims.(jwt.MapClaims)
	sub := claims["sub"].(string)

	it.logInfo(fmt.Sprintf("token sub: %v", sub))

	if len(sub) == 0 {
		return nil, errors.New("invalid JWT.sub")
	} else if it.acceptOriginalToken && sub == it.owner.gcp.clientEmail {
		return it.verifyOriginalToken(token)
	} else {
		return it.verifyFirebaseClientToken(token)
	}
}
