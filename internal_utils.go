package secure_backend

import (
	"crypto/sha512"
	"encoding/hex"
)

func sha512sum(s string) string {
	sum := sha512.Sum512([]byte(s))
	return hex.EncodeToString(sum[:])
}
