package main

import (
	"fmt"

	"gitlab.com/nmarley/go-bls-signatures"
)

func main() {
	sk, commitments, fragments, err := bls.ThresholdCreate(4, 6)
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
}
