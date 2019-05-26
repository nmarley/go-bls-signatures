package main

import (
	"fmt"

	"gitlab.com/nmarley/go-bls-signatures"
)

func main() {
	T := 4
	N := 6

	sk, commitments, fragments, err := bls.ThresholdCreate(T, N)
	if err != nil {
		panic(err)
	}

	fmt.Printf("sk: %x\n", sk.Serialize())

	fmt.Println("Got commitments:")
	for _, pk := range commitments {
		fmt.Printf("\t pk: %x\n", pk.Serialize())
	}

	fmt.Println("Got secret fragments:")
	for _, sk := range fragments {
		fmt.Printf("\t sk: %x\n", sk.Serialize())
	}

	verified := bls.ThresholdVerifySecretFragment(T, 1, sk, commitments)
	fmt.Printf("My fragment verified? : %v\n", verified)
}
