# go-bls-signatures

> Pure Go implemenation of <https://github.com/Chia-Network/bls-signatures>

---

**Warning: DO NOT USE THIS LIBRARY IN PRODUCTION**

I am not a cryptographer. This is for educational purposes only. Use at your own risk. *Thou hath been warned.*

---

This package itself implements the higher-level Chia BLS Signatures implementation. This is equivalent to the C++ code found in the `src/` dir in the repository referenced above.

The lower-level cryptography for the BLS12-381 curve is implemented in another (probably buggy) library, <https://github.com/nmarley/go-bls12-381>. That library is equivalent to the RELIC toolkit used by the Chia library, but specific to the BLS12-381 curve only.

This work and the other mentioned project is derived from an earlier version of [an existing project by Julian Meyer](https://github.com/phoreproject/bls) which is a port of the zkcrypto Rust implementation. That project does not implement the Chia spec.

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

	secretKey := bls.SecretKeyFromBytes(skBytes)
	publicKey := secretKey.PublicKey()
	fmt.Printf("public: %x\n", publicKey.Serialize())
	// public: 816782edc8f6815af5e256899d028c2dd2b6b243629262ea98da8df4b5755b24f85f78f5b124f2629b3fbdd2691cfb43
}
```

## Contributing

TODO ... contributing document

## License

[ISC](LICENSE)
