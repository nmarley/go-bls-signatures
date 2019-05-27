package bls

import (
	"bytes"
	"io"
	"math/big"
	"sort"
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

// SignWithCoefficient signs a message with lagrange coefficients.
//
// The T signatures signed this way (with the same parameters players and T)
// can be multiplied together to create a final signature for that message.
func (k *SecretKey) SignWithCoefficent(message []byte, playerIndex int, players []int) *Signature {
	h := HashG2(message)

	h.Mul()
	lambs := LagrangeCoeffsAtZero(players)

	//mh := NewMessageHashFromBytes(Hash256(message))
	//aggInfo := AggregationInfoFromMsgHash(k.PublicKey(), mh)
	//
	//return NewSignature(h.Mul(k.f.n), aggInfo)

	return &Signature{}
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

// SecretKeyFromBig returns a new key based on a big int in
// FR.
func SecretKeyFromBig(i *big.Int) *SecretKey {
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
		// not necessary b/c NewFR does this already, but might be a nice safety
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

		// TODO: finish this...

		//priv_pub_keys = sorted(zip(public_keys, private_keys))
		secPubKeys := make([]*KeyPair, len(publicKeys))
		for i := 0; i < len(publicKeys); i++ {
			secPubKeys[i] = &KeyPair{
				public: publicKeys[i],
				secret: secretKeys[i],
			}
		}
		// Sort keypairs by pub key
		sort.Sort(ByKeyPair(secPubKeys))

		computedTs := HashPKs(len(publicKeys), publicKeys)

		for i, kp := range secPubKeys {
			sumKeys.Add(sumKeys, new(big.Int).Mul(kp.secret.f.n, computedTs[i]))
			sumKeys.Mod(sumKeys, RFieldModulus)
		}
	}

	return SecretKeyFromBig(sumKeys)
}

// GetValue returns a copy of the underlying *FR
func (k *SecretKey) GetValue() *FR {
	return k.f.Copy()
}

// TODO: Move all this where it makes sense

// KeyPair is a public/secret key pair.
type KeyPair struct {
	public *PublicKey
	secret *SecretKey
}

// Less compares two keypairs
func (kp *KeyPair) Less(other *KeyPair) bool {
	return bytes.Compare(kp.public.Serialize(), other.public.Serialize()) == -1
}

// ByKeyPair implements sort.Interface for []*KeyPair
type ByKeyPair []*KeyPair

func (s ByKeyPair) Len() int           { return len(s) }
func (s ByKeyPair) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s ByKeyPair) Less(i, j int) bool { return s[i].Less(s[j]) }
