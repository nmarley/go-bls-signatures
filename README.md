# go-bls-signatures

> Pure Go implemenation of <https://github.com/Chia-Network/bls-signatures>

Implements the [BLS12-381 curve](https://z.cash/blog/new-snark-curve/).

Note that when referring to this curve, the "BLS" is "Barreto-Lynn-Scott", for the curve, not to be confused with the Boneh–Lynn–Shacham signature scheme, also called "BLS".

## Obligatory Warning: I am not a cryptographer. This should be considered alpha-level software at best. Use at your own risk!

This work is derived from an earlier version of [an existing project by Julian Meyer](https://github.com/phoreproject/bls) which is a port of the zkcrypto Rust implementation (that project does not implement the Chia spec).

## Install

```sh
go get -u gitlab.com/nmarley/go-bls-signatures
```

## Usage

```go
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
	// public: 816782edc8f6815af5e256899d028c2dd2b6b243629262ea98da8df4b5755b24f85f78f5b124f2629b3fbdd2691cfb43
}

```

## Contributing

TODO ... contributing document

## License

[ISC](LICENSE)
