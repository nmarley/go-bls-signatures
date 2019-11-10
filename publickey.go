package chiabls

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"sort"

	bls "github.com/nmarley/go-bls12-381"
)

// ...
const (
	PublicKeySize = bls.G1ElementSize
)

// PublicKey is a public key.
type PublicKey struct {
	p *bls.G1Projective
}

// NewPublicKey constructs a new PublicKey
func NewPublicKey(p *bls.G1Projective) *PublicKey {
	return &PublicKey{
		p: p.Copy(),
	}
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
	return publicKeyCompressPoint(p.p)
}

// publicKeyCompressPoint compresses the underlying curve point into a byte
// slice.
//
// Per the Chia spec, set the leftmost bit iff negative y. The other two unused
// bits are not used.
func publicKeyCompressPoint(p *bls.G1Projective) []byte {
	// Convert x-coord to byte slice
	g1Aff := p.ToAffine()

	// Create a byte array of exactly PublicKeySize bytes
	buf := [PublicKeySize]byte{}

	// Copy x-coord bytes into the byte array, but make sure and align them to
	// the right of the array. Meaning, if the integer backing the x-coord is
	// small, then there should be 0s at the front.
	//
	// Using an example with smaller numbers, let's say our x-coord is 7, but
	// we have a 2-byte array to hold it:
	//
	// n := 7
	// buf := [2]byte{}
	// copy(buf[:], n)  // <-- BUG!! This results in an array like [2]byte{0x7, 0x0}
	//                  //           What we *actually* want is:   [2]byte{0x0, 0x7}
	//
	// We want the starting index for copy destination to be the max array size
	// minus the length of the buffer we are copying. In this case, 2-len(n):
	//
	// copy(buf[2-len(n):], n)
	//
	// This results in what we want:  [2]byte{0x0, 0x7}
	//
	xBytes := g1Aff.GetXCoord().Bytes()
	copy(buf[bls.G1ElementSize-len(xBytes):], xBytes)

	// Right shift the Q bits once to get Half Q
	halfQ := new(big.Int).Rsh(bls.QFieldModulus, 1)

	// If the y coordinate is the bigger one of the two, set the first
	// bit to 1.
	y := g1Aff.GetYCoord()
	if y.Cmp(halfQ) == 1 {
		buf[0] |= 0x80
	}

	return buf[0:bls.G1ElementSize]
}

// Fingerprint returns the the first 4 bytes of hash256(serialize(pubkey))
func (p *PublicKey) Fingerprint() uint32 {
	buf := Hash256(p.Serialize())
	return binary.BigEndian.Uint32(buf[:4])
}

// Equal checks if two public keys are equal
func (p PublicKey) Equal(other PublicKey) bool {
	return p.p.Equal(other.p)
}

// Less compares two public keys by their serialized byte values
func (p *PublicKey) Less(other *PublicKey) bool {
	return bytes.Compare(p.Serialize(), other.Serialize()) == -1
}

// DeserializePublicKey calls PublicKeyFromBytes internally and is deprecated
func DeserializePublicKey(b []byte) (*PublicKey, error) {
	return PublicKeyFromBytes(b)
}

// PublicKeyFromBytes constructs a public key from a byte slice
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	if len(b) != PublicKeySize {
		return nil, fmt.Errorf("invalid public key bytes")
	}

	a, err := bls.DecompressG1(new(big.Int).SetBytes(b))
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
		// panic("Number of public keys must be at least 1")
		return nil
	}

	// Sort public keys
	sort.Sort(PkByBytes(publicKeys))

	var computedTs []*big.Int
	if secure {
		computedTs = HashPubKeys(len(publicKeys), publicKeys)
	}

	aggPk := bls.NewG1Projective(bls.FQOne, bls.FQOne, bls.FQZero)

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
