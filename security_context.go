package secure_backend

type SecurityContext interface {
	/*
		Returns Firebase auth based JWT verifier.

		see)
			- https://firebase.google.com/docs/auth?hl=en
			- https://github.com/firebase/firebase-admin-go/tree/master/auth
	*/
	NewFirebaseAuthVerifier() FirebaseAuthVerifier
}
