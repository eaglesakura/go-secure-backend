package secure_backend

import "context"

// Verifier for Firebase Auth token.
type FirebaseAuthVerifier interface {
	// Set custom logger.
	SetLogger(logger *Logger)

	// Support Original JWT Token.
	// sub = your GCP Project
	// default = deny.
	AcceptOriginalToken()

	// Verify Firebase Auth token.
	// supported)
	// 	- JWT: Firebase Custom Token source
	// 	- JWT: Firebase Auth Token
	// 		see) https://firebase.google.com/docs/auth/android/custom-auth?hl=en
	Verify(ctx context.Context, token string) (*VerifiedFirebaseAuthToken, error)
}
