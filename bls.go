package bls

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
)

// Sizes of g1/g2 elements
// TODO: Probably move these somewhere else...
const (
	G1ElementSize = 48
	G2ElementSize = 96
)

// ...
const (
	SecretKeySize = 32
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
	switch len(b) {
	case G1ElementSize:
		a, err := DecompressG1(new(big.Int).SetBytes(b))
		if err != nil {
			return nil, err
		}

		return &PublicKey{p: a.ToProjective()}, nil

	case G1ElementSize * 2:
		g := G1Affine{}

		// Set points given raw bytes for coordinates
		g.SetRawBytes(b)

		return &PublicKey{p: g.ToProjective()}, nil
	}

	return nil, fmt.Errorf("invalid pubkey bytes")
}

// SecretKey represents a BLS private key.
type SecretKey struct {
	f *FR
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

// AtePairingMulti ...
//
// Computes multiple pairings at once. This is more efficient, since we can
// multiply all the results of the miller loops, and perform just one final
// exponentiation.
func AtePairingMulti(ps []*G1Projective, qs []*G2Projective) *FQ12 {
	// t = default_ec.x + 1
	// T = abs(t - 1)
	negX := new(big.Int).Neg(blsX)
	t := new(big.Int).Add(negX, bigOne)
	bigT := new(big.Int).Abs(new(big.Int).Sub(t, bigOne))

	// prod = Fq12.one(ec.q)
	prod := FQ12One.Copy()

	//for i in range(len(Qs)):
	//     prod *= miller_loop(T, Ps[i], Qs[i], ec)
	for i, q := range qs {
		p := ps[i]
		// TODO/NGM: Just inline this once finished w/debugging
		xml := XMillerLoop(bigT, p, q)
		prod = prod.Mul(xml)
	}

	// TODO/NGM: Inline this when done debugging
	final := XFinalExponentiation(prod)
	return final
}

// By implements sort.Interface for []MapKey
type By []MapKey

func (s By) Len() int           { return len(s) }
func (s By) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s By) Less(i, j int) bool { return bytes.Compare(s[i][:], s[j][:]) == -1 }

// HashPKs ... no fucking idea. :/
//
// Construction from https://eprint.iacr.org/2018/483.pdf
// Two hashes are performed for speed.
func HashPKs(numOutputs int, publicKeys []*PublicKey) []*big.Int {
	inputBytes := make([]byte, len(publicKeys)*PublicKeySize)
	for i, k := range publicKeys {
		pkBytes := k.Serialize()
		copy(inputBytes[(i*PublicKeySize):], pkBytes)
	}

	pkHash := Hash256(inputBytes)
	computedTs := make([]*big.Int, numOutputs)
	for i := uint32(0); i < uint32(numOutputs); i++ {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], i)
		innerHash := Hash256(append(b[:], pkHash...))
		t := new(big.Int).SetBytes(innerHash)
		t.Mod(t, RFieldModulus)
		computedTs[i] = t
	}

	return computedTs
}

// MessageSet and associate funcs are a syntactic sugar wrapper around a map
type MessageSet map[MessageHash]struct{}

func NewMessageSet() *MessageSet {
	ms := make(MessageSet)
	return &ms
}
func (ms *MessageSet) AddMsg(msg *MessageHash) {
	(*ms)[*msg] = struct{}{}
}
func (ms *MessageSet) HasMsg(msg *MessageHash) bool {
	_, found := (*ms)[*msg]
	return found
}
func (ms *MessageSet) Len() int {
	return len(*ms)
}
