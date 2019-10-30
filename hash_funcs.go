package bls

import (
	"crypto/hmac"
	"crypto/sha256"
)

// Hmac256 returns a HMAC using SHA256.
func Hmac256(m, key []byte) []byte {
	// Create a new HMAC by defining the hash type and the key (as byte array)
	hash := hmac.New(sha256.New, key)

	// Write data to it
	hash.Write(m)

	// Get the result
	return hash.Sum(nil)
}
