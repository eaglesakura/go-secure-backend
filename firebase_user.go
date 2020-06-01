package secure_backend

import "fmt"

type FirebaseUser struct {
	/*
		Firebase user id.
	*/
	Id string
}

func (it *FirebaseUser) String() string {
	return fmt.Sprintf("FirebaseUser(%v)", it.Id)
}
