package secure_backend

/*
Verifier for Firebase Auth token.
*/
type FirebaseAuthVerifier interface {
	/*
		Support Original JWT Token.
		sub = your GCP Project
		default = deny.
	*/
	AcceptOriginalToken() FirebaseAuthVerifier

	/*
		Verify Firebase Auth token.

		supported)
			- JWT: Firebase Custom Token source
			- JWT: Firebase Auth Token
				see) https://firebase.google.com/docs/auth/android/custom-auth?hl=en
	*/
	Verify(token string) (*VerifiedFirebaseAuthToken, error)
}
