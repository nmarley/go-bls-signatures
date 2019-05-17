package bls

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"sort"
)

// ...
const (
	PublicKeySize = G1ElementSize
)

// PublicKey is a public key.
type PublicKey struct {
	p *G1Projective
}

// String implements the Stringer interface
func (p PublicKey) String() string {
	return fmt.Sprintf("%096x", p.Serialize())
}

// StringShort ...
func (p PublicKey) StringShort() string {
	hexStr := fmt.Sprintf("%096x", p.Serialize())
	return hexStr[0:5] + ".." + hexStr[(len(hexStr)-5):]
}

// Debug ...
func (p *PublicKey) Debug() string {
	return p.p.ToAffine().PP()
}

// Serialize serializes a public key to a byte slice
func (p *PublicKey) Serialize() []byte {
	return CompressG1(p.p.ToAffine())
}

// Fingerprint returns the the first 4 bytes of hash256(serialize(pubkey))
func (p *PublicKey) Fingerprint() uint32 {
	buf := Hash256(p.Serialize())
	return binary.BigEndian.Uint32(buf[:4])
}

// Equals checks if two public keys are equal
func (p PublicKey) Equals(other PublicKey) bool {
	return p.p.Equal(other.p)
}

// Less compares two public keys by their serialized byte values
func (p *PublicKey) Less(other *PublicKey) bool {
	return bytes.Compare(p.Serialize(), other.Serialize()) == -1
}

// DeserializePublicKey deserializes a public key from bytes.
func DeserializePublicKey(b []byte) (*PublicKey, error) {
	if len(b) != PublicKeySize {
		return nil, fmt.Errorf("invalid public key bytes")
	}

	a, err := DecompressG1(new(big.Int).SetBytes(b))
	if err != nil {
		return nil, err
	}

	return &PublicKey{p: a.ToProjective()}, nil
}

// AggregatePublicKeys aggregates multiple public keys into one. The secure
// flag securely aggregates multiple public keys into one by exponentiating the
// keys with the pubKey hashes first.
func AggregatePublicKeys(publicKeys []*PublicKey, secure bool) *PublicKey {
	if len(publicKeys) == 0 {
		// TODO: don't panic
		panic("Number of public keys must be at least 1")
	}

	// Sort public keys
	sort.Sort(PkByBytes(publicKeys))

	// TODO: potential optimization:
	// consider splitting this so these don't have to be calculated for non-secure
	computedTs := HashPKs(len(publicKeys), publicKeys)

	aggPk := NewG1Projective(FQOne, FQOne, FQZero)

	for i, pk := range publicKeys {
		tempG1 := pk.p.Copy()
		if secure {
			tempG1 = tempG1.Mul(computedTs[i])
		}
		aggPk = aggPk.Add(tempG1)
	}

	return &PublicKey{p: aggPk}
}

// PkByBytes implements sort.Interface for []*PublicKey, and
// sorts by serialized byte value
type PkByBytes []*PublicKey

func (s PkByBytes) Len() int           { return len(s) }
func (s PkByBytes) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s PkByBytes) Less(i, j int) bool { return s[i].Less(s[j]) }
