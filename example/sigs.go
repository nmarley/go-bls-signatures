package main

import (
	// "bytes"
	"fmt"
	// "crypto/sha256"

	bls "gitlab.com/nmarley/go-bls-signatures"
)

func main() {
	m1 := []byte{1, 2, 3, 40}
	m2 := []byte{5, 6, 70, 201}

	sk1 := bls.SecretKeyFromSeed([]byte{1, 2, 3, 4, 5})
	sk2 := bls.SecretKeyFromSeed([]byte{1, 2, 3, 4, 5, 6})

	sig1 := sk1.Sign(m1)
	sig2 := sk2.Sign(m2)

	sigL := bls.AggregateSignatures([]*bls.Signature{sig1, sig2})

	quot1 := sigL.DivideBy([]*bls.Signature{sig1})
	fmt.Printf("quot1: %x\n", quot1.Serialize())
	fmt.Printf("sig2: %x\n", sig2.Serialize())
}
