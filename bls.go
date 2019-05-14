package bls

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/big"
	"sort"
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
	SignatureSize = G2ElementSize
)

// Signature is a message signature.
type Signature struct {
	s *G2Projective
}

// Debug ...
func (s *Signature) Debug() string {
	return s.s.ToAffine().PP()
}

// Serialize serializes a signature.
func (s *Signature) Serialize(compressed bool) []byte {
	if compressed {
		return CompressG2(s.s.ToAffine())
	}

	// else serialize uncompressed
	affine := s.s.ToAffine()
	out := [G2ElementSize * 2]byte{}
	if affine.infinity {
		out[0] = (1 << 6)
		return out[:]
	}

	return affine.SerializeBytes()
}

// DeserializeSignature deserializes a signature from bytes.
func DeserializeSignature(b []byte) (*Signature, error) {
	switch len(b) {
	case G2ElementSize:
		a, err := DecompressG2(new(big.Int).SetBytes(b))
		if err != nil {
			return nil, err
		}

		return &Signature{s: a.ToProjective()}, nil

	case G2ElementSize * 2:
		a := G2Affine{}

		// Set points given raw bytes for coordinates
		a.SetRawBytes(b)

		return &Signature{s: a.ToProjective()}, nil
	}

	return nil, fmt.Errorf("invalid signature bytes")
}

// Copy returns a copy of the signature.
func (s *Signature) Copy() *Signature {
	return &Signature{s.s.Copy()}
}

// PublicKey is a public key.
type PublicKey struct {
	p *G1Projective
}

// String ...
func (p PublicKey) String() string {
	return p.p.String()
}

// Debug ...
func (p *PublicKey) Debug() string {
	return p.p.ToAffine().PP()
}

// Serialize serializes a public key to bytes.
//
// TODO: Probably just disallow uncompressed altogether
// Since Chia does not use this, it does not make sense to add complexity to
// the codebase for no reason or keep it there "just because".
func (p *PublicKey) Serialize(compressed bool) []byte {
	if compressed {
		return CompressG1(p.p.ToAffine())
	}

	// else serialize uncompressed
	affine := p.p.ToAffine()
	return affine.SerializeBytes()
}

// Fingerprint returns the the first 4 bytes of hash256(serialize(pubkey))
func (p *PublicKey) Fingerprint() uint32 {
	buf := Hash256(p.Serialize(true))
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
		NewFR(new(big.Int).Mod(new(big.Int).SetBytes(hashed), RFieldModulus)),
	}
}

// PublicKey returns the public key.
func (s *SecretKey) PublicKey() *PublicKey {
	return PrivToPub(s)
}

// String implements the Stringer interface.
func (s SecretKey) String() string {
	return s.f.String()
}

// Serialize serializes a secret key to bytes.
func (s SecretKey) Serialize() []byte {
	return s.f.n.Bytes()
}

// DeserializeSecretKey deserializes a secret key from
// bytes.
func DeserializeSecretKey(b []byte) *SecretKey {
	return &SecretKey{&FR{new(big.Int).SetBytes(b)}}
}

// Sign signs a message with a secret key.
func Sign(message []byte, key *SecretKey) *Signature {
	h := XHashG2(message)
	return &Signature{s: h.Mul(key.f.n)}
}

// PrivToPub converts the private key into a public key.
func PrivToPub(k *SecretKey) *PublicKey {
	return &PublicKey{p: G1AffineOne.Mul(k.f.n)}
}

// RandKey generates a random secret key.
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

// Verify verifies a signature against a message and a public key.
func Verify(m []byte, pub *PublicKey, sig *Signature, domain uint64) bool {
	h := HashG2(m, domain)
	lhs := Pairing(G1ProjectiveOne, sig.s)
	rhs := Pairing(pub.p, h)
	return lhs.Equals(rhs)
}

// XVerify verifies a signature against a message and a public key.
//
// This implementation of verify has several steps. First, it reorganizes the
// pubkeys and messages into groups, where each group corresponds to a message.
// Then, it checks if the siganture has info on how it was aggregated. If so,
// we exponentiate each pk based on the exponent in the AggregationInfo.  If
// not, we find public keys that share messages with others, and aggregate all
// of these securely (with exponents.).  Finally, since each public key now
// corresponds to a unique message (since we grouped them), we can verify using
// the distinct verification procedure.
func XVerify(m []byte, pub *PublicKey, sig *Signature) bool {
	h := Hash256(m)

	// TODO/NGM: consider forcing [32]byte for all hashes, to prevent further
	// copy bugs...
	agginfo := AggregationInfoFromMsgHash(pub, h)
	messageHashes := agginfo.GetMessageHashes()
	publicKeys := agginfo.GetPublicKeys()
	if len(messageHashes) != len(publicKeys) {
		return false
	}

	hashToPublicKeys := make(map[MessageHash][]*PublicKey)

	// usedPKs is to keep track and prevent duplicate hash/pubkeys
	usedPKs := make(map[MapKey]struct{})

	// NGM: I honestly think this loop doesn't make sense... let's wait and see.
	// Look thru each messageHash from agginfo
	for i, hash := range messageHashes {
		// Copy hash slice into MessageHash var
		var mh MessageHash
		copy(mh[:], hash)

		// Convenience accessor for the public key
		pk := publicKeys[i]
		mk := NewMapKey(pk, mh)

		// Check if messageHash value exists in map
		val, ok := hashToPublicKeys[mh]
		if ok {
			_, found := usedPKs[mk]
			if !found {
				hashToPublicKeys[mh] = append(val, pk)
				usedPKs[mk] = struct{}{}
			}
		} else {
			hashToPublicKeys[mh] = []*PublicKey{pk}
			usedPKs[mk] = struct{}{}
		}
	}

	var finalMessageHashes []MessageHash
	var finalPublicKeys []*G1Projective
	var mappedHashes []*G2Projective

	for mh, keys := range hashToPublicKeys {
		publicKeySum := NewG1Projective(FQOne, FQOne, FQZero)
		for _, k := range keys {
			mk := NewMapKey(k, mh)
			exponent := agginfo.Tree[mk]
			sum := k.p.Mul(exponent)
			publicKeySum = publicKeySum.Add(sum)
		}
		finalMessageHashes = append(finalMessageHashes, mh)
		finalPublicKeys = append(finalPublicKeys, publicKeySum)
		mappedHashes = append(mappedHashes, XHashG2PreHashed(mh[:]))
	}

	fq := NewFQ(new(big.Int).Sub(RFieldModulus, bigOne))
	g1 := NewG1Affine(NewFQ(g1GeneratorX), NewFQ(g1GeneratorY)).Mul(fq.n)

	// Gather a list of p's and q's to send to AtePairingMulti
	ps := []*G1Projective{g1}
	ps = append(ps, finalPublicKeys...)
	qs := []*G2Projective{sig.s}
	qs = append(qs, mappedHashes...)

	res := AtePairingMulti(ps, qs)

	return FQ12One.Equals(res)
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

// AggregateSignatures adds up all of the signatures.
func AggregateSignatures(s []*Signature) *Signature {
	newSig := &Signature{s: G2ProjectiveZero.Copy()}
	for _, sig := range s {
		newSig.Aggregate(sig)
	}
	return newSig
}

// Aggregate adds one signature to another
func (s *Signature) Aggregate(other *Signature) {
	newS := s.s.Add(other.s)
	s.s = newS
}

// String implements the Stringer interface
func (s Signature) String() string {
	return fmt.Sprintf("%096x", s.Serialize(true))
}

// AggregatePublicKeys adds public keys together.
func AggregatePublicKeys(p []*PublicKey) *PublicKey {
	newPub := &PublicKey{p: G1ProjectiveZero.Copy()}
	for _, pub := range p {
		newPub.Aggregate(pub)
	}
	return newPub
}

// Aggregate adds two public keys together.
func (p *PublicKey) Aggregate(other *PublicKey) {
	newP := p.p.Add(other.p)
	p.p = newP
}

// Copy copies the public key and returns it.
func (p *PublicKey) Copy() *PublicKey {
	return &PublicKey{p: p.p.Copy()}
}

// NewAggregateSignature creates a blank aggregate signature.
func NewAggregateSignature() *Signature {
	return &Signature{s: G2ProjectiveZero.Copy()}
}

// NewAggregatePubkey creates a blank public key.
func NewAggregatePubkey() *PublicKey {
	return &PublicKey{p: G1ProjectiveZero.Copy()}
}

// implement `Interface` in sort package.
type sortableByteArray [][]byte

func (b sortableByteArray) Len() int {
	return len(b)
}

func (b sortableByteArray) Less(i, j int) bool {
	// bytes package already implements Comparable for []byte.
	switch bytes.Compare(b[i], b[j]) {
	case -1:
		return true
	case 0, 1:
		return false
	default:
		log.Panic("not fail-able with `bytes.Comparable` bounded [-1, 1].")
		return false
	}
}

func (b sortableByteArray) Swap(i, j int) {
	b[j], b[i] = b[i], b[j]
}

func sortByteArrays(src [][]byte) [][]byte {
	sorted := sortableByteArray(src)
	sort.Sort(sorted)
	return sorted
}

// VerifyAggregate verifies each public key against each message.
func (s *Signature) VerifyAggregate(pubKeys []*PublicKey, msgs [][]byte, domain uint64) bool {
	if len(pubKeys) != len(msgs) {
		return false
	}

	// messages must be distinct
	msgsSorted := sortByteArrays(msgs)
	lastMsg := []byte(nil)

	// check for duplicates
	for _, m := range msgsSorted {
		if bytes.Equal(m, lastMsg) {
			return false
		}
		lastMsg = m
	}

	lhs := Pairing(G1ProjectiveOne, s.s)
	rhs := FQ12One.Copy()
	for i := range pubKeys {
		h := HashG2(msgs[i], domain)
		rhs.MulAssign(Pairing(pubKeys[i].p, h))
	}
	return lhs.Equals(rhs)
}

// VerifyAggregateCommon verifies each public key against a message.
// This is vulnerable to rogue public-key attack. Each user must
// provide a proof-of-knowledge of the public key.
func (s *Signature) VerifyAggregateCommon(pubKeys []*PublicKey, msg []byte, domain uint64) bool {
	h := HashG2(msg, domain)
	lhs := Pairing(G1ProjectiveOne, s.s)
	rhs := FQ12One.Copy()
	for _, p := range pubKeys {
		rhs.MulAssign(Pairing(p.p, h))
	}
	return lhs.Equals(rhs)
}
