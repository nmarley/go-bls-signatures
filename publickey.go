package bls

import (
	"encoding/binary"
	"fmt"
	"math/big"
)

// ...
const (
	PublicKeySize = G1ElementSize
)

// PublicKey is a public key.
type PublicKey struct {
	p *G1Projective
}

// String ...
func (p PublicKey) String() string {
	return p.p.String()
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
}
