package bls

import (
	"io"
	"math/big"
)

// ...
const (
	SecretKeySize = 32
)

// SecretKey represents a BLS private key.
type SecretKey struct {
	f *FR
}

// NewSecretKey initializes a new BLS secret key from a *FR.
func NewSecretKey(f *FR) *SecretKey {
	return &SecretKey{
		f: f,
	}
}

// SecretKeyFromSeed generates a private key from a seed, similar to HD key
// generation (hashes the seed), and reduces it mod the group order.
func SecretKeyFromSeed(seed []byte) *SecretKey {
	hmacKey := []byte("BLS private key seed")

	hashed := Hmac256(seed, hmacKey)
	return &SecretKey{
		NewFR(new(big.Int).SetBytes(hashed)),
	}
}

// PublicKey returns the public key.
func (k *SecretKey) PublicKey() *PublicKey {
	return &PublicKey{
		p: G1AffineOne.Mul(k.f.n),
	}
}

// String implements the Stringer interface.
func (k SecretKey) String() string {
	return k.f.String()
}

// Serialize serializes a secret key to a byte slice
func (k *SecretKey) Serialize() []byte {
	// Ensure we return 32 bytes with bits aligned to the right
	buf := [SecretKeySize]byte{}
	skBytes := k.f.n.Bytes()
	copy(buf[SecretKeySize-len(skBytes):], skBytes)
	return buf[0:SecretKeySize]
}

// DeserializeSecretKey deserializes a secret key from bytes.
func DeserializeSecretKey(b []byte) *SecretKey {
	return &SecretKey{
		NewFR(new(big.Int).SetBytes(b)),
	}
}

// Sign signs a message with a secret key.
func (k *SecretKey) Sign(message []byte) *Signature {
	h := HashG2(message)
	mh := NewMessageHashFromBytes(Hash256(message))
	aggInfo := AggregationInfoFromMsgHash(k.PublicKey(), mh)

	return NewSignature(h.Mul(k.f.n), aggInfo)
}

// RandKey generates a random secret key
func RandKey(r io.Reader) (*SecretKey, error) {
	k, err := RandFR(r)
	if err != nil {
		return nil, err
	}
	s := &SecretKey{f: k}
	return s, nil
}

// KeyFromBig returns a new key based on a big int in
// FR.
func KeyFromBig(i *big.Int) *SecretKey {
	return &SecretKey{f: NewFR(i)}
}

// AggregateSecretKeys aggregates multiple secret keys into one. The secure
// flag securely aggregates multiple secret keys into one by exponentiating the
// keys with the pubKey hashes first.
func AggregateSecretKeys(secretKeys []*SecretKey, publicKeys []*PublicKey, secure bool) *SecretKey {
	sumKeys := new(big.Int)
	if !secure {
		for _, sk := range secretKeys {
			sumKeys.Add(sumKeys, sk.f.ToBig())
		}
		sumKeys.Mod(sumKeys, RFieldModulus)
	} else {
		if len(publicKeys) == 0 {
			// TODO: Don't panic
			panic("must include public keys in secure aggregation")
		}
		if len(publicKeys) != len(secretKeys) {
			// TODO: Don't panic
			panic("invalid number of keys")
		}

		//secPubKeys
		// TODO: finish this...
	}

	return KeyFromBig(sumKeys)
}
