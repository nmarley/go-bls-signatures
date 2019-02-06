package bls

import (
	"crypto/hmac"
	"crypto/sha256"
)

// Hash256 function with 256 bit outputs.
func Hash256(m []byte) []byte {
	h := sha256.New()
	h.Write(m)
	return h.Sum(nil)
}

// Hmac256 returns a HMAC using SHA256.
func Hmac256(m, key []byte) []byte {
	// Create a new HMAC by defining the hash type and the key (as byte array)
	hash := hmac.New(sha256.New, key)

	// Write data to it
	hash.Write(m)

	// Get the result
	return hash.Sum(nil)
}
