package main

import (
	"encoding/hex"
	"fmt"

	bls "gitlab.com/nmarley/go-bls-signatures"
)

func main() {
	skHex := "2ac124c0aa1808e590ff1f94d67a53970ae982aa30bbe261ff1cb2ad15b7452a"
	skBytes, _ := hex.DecodeString(skHex)

	secretKey := bls.DeserializeSecretKey(skBytes)
	publicKey := secretKey.PublicKey()
	fmt.Printf("public: %x\n", publicKey.Serialize())
}

// secret: "2ac124c0aa1808e590ff1f94d67a53970ae982aa30bbe261ff1cb2ad15b7452a",
// public: "816782edc8f6815af5e256899d028c2dd2b6b243629262ea98da8df4b5755b24f85f78f5b124f2629b3fbdd2691cfb43",
