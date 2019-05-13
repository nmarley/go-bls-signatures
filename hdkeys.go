package bls

import (
	"math/big"
)

// ExtendedSecretKey represents a BLS extended private key.
type ExtendedSecretKey struct {
	Version           uint32
	Depth             uint8
	ParentFingerprint uint32
	ChildNumber       uint32
	SecretKey         *SecretKey
	ChainCode         *big.Int
}

// thing ...
const (
	ExtendedSecretKeyVersion = 1
	ExtendedSecretKeySize    = 77
)

// SecretKeyFromSeed generates a private key from a seed, similar to HD key
// generation (hashes the seed), and reduces it mod the group order.
func ExtendedSecretKeyFromSeed(seed []byte) *ExtendedSecretKey {
	// TODO: Comment me later
	hmacKey := []byte("BLS HD seed")

	// TODO: Comment me later
	iLeft := Hmac256(append(seed, []byte{0}...), hmacKey)
	iRight := Hmac256(append(seed, []byte{1}...), hmacKey)

	// TODO: Comment me later
	skInt := new(big.Int).SetBytes(iLeft)
	skInt = new(big.Int).Mod(skInt, RFieldModulus)

	// it appears this is not needed b/c the byte slice is not used internally
	//// TODO: Comment me later
	////buf := [SecretKeySize]byte{}
	//
	//// TODO: Comment me later
	////skBytes := skInt.Bytes()
	//
	//// TODO: Comment me later
	////copy(buf[SecretKeySize-len(skBytes):], skBytes)

	// TODO: Comment me later
	sk := DeserializeSecretKey(skInt.Bytes())

	return &ExtendedSecretKey{
		Version:           ExtendedSecretKeyVersion,
		Depth:             0,
		ParentFingerprint: 0,
		ChildNumber:       0,
		ChainCode:         new(big.Int).SetBytes(iRight),
		SecretKey:         sk,
	}
}

// GetPublicKey ...
func (k *ExtendedSecretKey) GetPublicKey() *PublicKey {
	return k.SecretKey.PublicKey()
}

// GetChainCode ...
func (k *ExtendedSecretKey) GetChainCode() *big.Int {
	return k.ChainCode
}

// HD keys
//
// esk = ExtendedPrivateKey([1, 50, 6, 244, 24, 199, 1, 25])
// esk.publicKeyFigerprint
//
// 0xa4700b27
//
//
// esk.chainCode
//
// 0xd8b12555b4cc5578951e4a7c80031e22019cc0dce168b3ed88115311b8feb1e3
//
//
// esk77 = esk.privateChild(77 + 2^31)
// esk77.publicKeyFingerprint
//
// 0xa8063dcf
//
//
// esk77.chainCode
//
// 0xf2c8e4269bb3e54f8179a5c6976d92ca14c3260dd729981e9d15f53049fd698b
//
//
// esk.privateChild(3).privateChild(17).publicKeyFingerprint
//
// 0xff26a31f
//
//
// esk.extendedPublicKey.publicChild(3).publicChild(17).publicKeyFingerprint
//
// 0xff26a31f
