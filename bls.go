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
	s  *G2Projective
	ai *AggregationInfo
}

// NewSignature ...
func NewSignature(p *G2Projective, ai *AggregationInfo) *Signature {
	return &Signature{
		s:  p,
		ai: ai,
	}
}

// SetAggregationInfo ... TODO
func (s *Signature) SetAggregationInfo(ai *AggregationInfo) {
	s.ai = ai
}

// Debug ...
func (s *Signature) Debug() string {
	return s.s.ToAffine().PP()
}

// Serialize serializes a signature to a byte slice
func (s *Signature) Serialize() []byte {
	return CompressG2(s.s.ToAffine())
}

// DeserializeSignature deserializes a signature from bytes.
func DeserializeSignature(b []byte) (*Signature, error) {
	if len(b) != SignatureSize {
		return nil, fmt.Errorf("invalid signature bytes")
	}
	a, err := DecompressG2(new(big.Int).SetBytes(b))
	if err != nil {
		return nil, err
	}

	return NewSignature(a.ToProjective(), nil), nil
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

// Verify verifies a signature against a message and a public key.
//
// This implementation of verify has several steps. First, it reorganizes the
// pubkeys and messages into groups, where each group corresponds to a message.
// Then, it checks if the siganture has info on how it was aggregated. If so,
// we exponentiate each pk based on the exponent in the AggregationInfo.  If
// not, we find public keys that share messages with others, and aggregate all
// of these securely (with exponents.).  Finally, since each public key now
// corresponds to a unique message (since we grouped them), we can verify using
// the distinct verification procedure.
func (s *Signature) Verify() bool {
	if s.ai == nil {
		return false
	}

	agginfo := s.ai
	messageHashes := agginfo.Hashes
	publicKeys := agginfo.PublicKeys
	if len(messageHashes) != len(publicKeys) {
		return false
	}

	hashToPublicKeys := make(map[*MessageHash][]*PublicKey)

	// usedPKs is to keep track and prevent duplicate hash/pubkeys
	usedPKs := make(map[MapKey]struct{})

	// NGM: I honestly think this loop doesn't make sense... let's wait and see.
	// Look thru each messageHash from agginfo
	for i, mh := range messageHashes {
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

	// TODO: Only once all Chia test vectors passing, review this and see if
	// finalMessageHashes / mappedhashes is really needed.
	var finalMessageHashes []*MessageHash
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
		mappedHashes = append(mappedHashes, HashG2PreHashed(mh[:]))
	}

	fq := NewFQ(new(big.Int).Sub(RFieldModulus, bigOne))
	g1 := NewG1Affine(NewFQ(g1GeneratorX), NewFQ(g1GeneratorY)).Mul(fq.n)

	// Gather a list of p's and q's to send to AtePairingMulti
	// TODO: Could optimize here...
	ps := []*G1Projective{g1}
	ps = append(ps, finalPublicKeys...)
	qs := []*G2Projective{s.s}
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

// AggregateSignaturesSimple aggregate signatures by multiplying them together.
// This is NOT secure against rogue public key attacks, so do not use this for
// signatures on the same message.
func AggregateSignaturesSimple(signatures []*Signature) *Signature {
	aggSig := G2ProjectiveZero.Copy()

	for _, sig := range signatures {
		aggSig = aggSig.Add(sig.s)
	}

	return NewSignature(aggSig, nil)
}

//def aggregate_sigs_simple(signatures):
//    for sig in signatures:
//        agg_sig += sig.value
//
//    return Signature.from_g2(agg_sig)

//// aggregates many signatures on messages, some of
//// which may be identical. The returned signature contains
//// information on how the aggregation was done (AggragationInfo).
//static Signature Aggregate(std::vector<Signature> const &sigs);

// AggregateSignatures aggregates many (aggregate) signatures, using a
// combination of simple and secure aggregation. Signatures are grouped based
// on which ones share common messages, and these are all merged securely.
func AggregateSignatures(signatures []*Signature) *Signature {
	//fmt.Println("NGMgo s:", signatures)

	type publicKeysList []*PublicKey
	type messageHashesList []*MessageHash

	var publicKeys []publicKeysList
	var messageHashes []messageHashesList

	for _, sig := range signatures {
		if sig.ai == nil {
			// TODO: error, do not panic
			panic("Each signature must have a valid aggregation info")
		}
		publicKeys = append(publicKeys, sig.ai.PublicKeys)
		messageHashes = append(messageHashes, sig.ai.Hashes)
	}

	// Find colliding vectors, save colliding messages
	messagesSet := NewMessageSet()
	collidingMessagesSet := NewMessageSet()

	for _, hashList := range messageHashes {
		messagesSetLocal := NewMessageSet()
		for _, msg := range hashList {
			foundGlobal := messagesSet.HasMsg(msg)
			foundLocal := messagesSetLocal.HasMsg(msg)
			if foundGlobal && !foundLocal {
				collidingMessagesSet.AddMsg(msg)
			}
			messagesSet.AddMsg(msg)
			messagesSetLocal.AddMsg(msg)
		}
	}

	if collidingMessagesSet.Len() == 0 {
		// There are no colliding messages between the groups, so we
		// will just aggregate them all simply. Note that we assume
		// that every group is a valid aggregate signature. If an invalid
		// or insecure signature is given, and invalid signature will
		// be created. We don't verify for performance reasons.

		// TODO: Test this!!!
		aggInfos := make([]*AggregationInfo, len(signatures))
		for i, sig := range signatures {
			aggInfos[i] = sig.ai
		}
		finalAggInfo := MergeAggregationInfos(aggInfos)

		finalSig := AggregateSignaturesSimple(signatures)
		finalSig.SetAggregationInfo(finalAggInfo)

		return finalSig
	}

	// There are groups that share messages, therefore we need
	// to use a secure form of aggregation. First we find which
	// groups collide, and securely aggregate these. Then, we
	// use simple aggregation at the end.

	var collidingSigs []*Signature
	var nonCollidingSigs []*Signature

	// Lists of lists
	var collidingMessageHashes []messageHashesList
	var collidingPublicKeys []publicKeysList

	for i, sig := range signatures {
		groupCollides := false
		for _, msg := range messageHashes[i] {
			if collidingMessagesSet.HasMsg(msg) {
				groupCollides = true
				collidingSigs = append(collidingSigs, sig)
				collidingMessageHashes = append(collidingMessageHashes, messageHashes[i])
				collidingPublicKeys = append(collidingPublicKeys, publicKeys[i])
				break
			}
		}
		if !groupCollides {
			nonCollidingSigs = append(nonCollidingSigs, sig)
		}
	}

	// Sort signatures by their aggregation info
	sort.Sort(SigsByAI(collidingSigs))

	var sortKeysSorted []MapKey

	// Arrange all public keys in sorted order, by (m, pk)
	for i := 0; i < len(collidingPublicKeys); i++ {
		for j := 0; j < len(collidingPublicKeys[i]); j++ {
			mh := collidingMessageHashes[i][j]
			pk := collidingPublicKeys[i][j]
			sortKeysSorted = append(sortKeysSorted, NewMapKey(pk, mh))
		}
	}

	// Sort lexicographically binary, then split out pks / hashes
	sort.Sort(By(sortKeysSorted))
	var sortedPublicKeys []*PublicKey
	for _, mk := range sortKeysSorted {
		buf := [PublicKeySize]byte{}
		copy(buf[:], mk[MessageHashSize:])
		pk, err := DeserializePublicKey(buf[:])
		if err != nil {
			// todo: don't panic
			panic("oh shit")
		}
		sortedPublicKeys = append(sortedPublicKeys, pk)
	}

	computed_Ts := HashPKs(len(collidingSigs), sortedPublicKeys)

	// Raise each sig to a power of each t,
	// and multiply all together into agg_sig
	aggSig := NewG2Projective(FQ2One, FQ2One, FQ2Zero)
	for i, sig := range collidingSigs {
		aggSig = aggSig.Add(sig.s.Mul(computed_Ts[i]))
	}

	aggInfos := make([]*AggregationInfo, len(signatures))
	for i, sig := range signatures {
		aggInfos[i] = sig.ai
	}

	finalAggInfo := MergeAggregationInfos(aggInfos)
	finalSig := NewSignature(aggSig, nil)
	finalSig.SetAggregationInfo(finalAggInfo)

	return finalSig
}

// SigsByAI implements sort.Interface for []*Signature, and sorts by
// AggregationInfo
type SigsByAI []*Signature

func (s SigsByAI) Len() int           { return len(s) }
func (s SigsByAI) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s SigsByAI) Less(i, j int) bool { return s[i].ai.Less(s[j].ai) }

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

//// Aggregate adds one signature to another
//func (s *Signature) Aggregate(other *Signature) {
//	newS := s.s.Add(other.s)
//	s.s = newS
//}

// String implements the Stringer interface
func (s Signature) String() string {
	return fmt.Sprintf("%096x", s.Serialize())
}

//// AggregatePublicKeys adds public keys together.
//func AggregatePublicKeys(p []*PublicKey) *PublicKey {
//	newPub := &PublicKey{p: G1ProjectiveZero.Copy()}
//	for _, pub := range p {
//		newPub.Aggregate(pub)
//	}
//	return newPub
//}

//// Aggregate adds two public keys together.
//func (p *PublicKey) Aggregate(other *PublicKey) {
//	newP := p.p.Add(other.p)
//	p.p = newP
//}

//// NewAggregateSignature creates a blank aggregate signature.
//func NewAggregateSignature() *Signature {
//	return &Signature{s: G2ProjectiveZero.Copy()}
//}
//
//// NewAggregatePubkey creates a blank public key.
//func NewAggregatePubkey() *PublicKey {
//	return &PublicKey{p: G1ProjectiveZero.Copy()}
//}

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
//func (s *Signature) VerifyAggregate(pubKeys []*PublicKey, msgs [][]byte, domain uint64) bool {
//	if len(pubKeys) != len(msgs) {
//		return false
//	}
//
//	// messages must be distinct
//	msgsSorted := sortByteArrays(msgs)
//	lastMsg := []byte(nil)
//
//	// check for duplicates
//	for _, m := range msgsSorted {
//		if bytes.Equal(m, lastMsg) {
//			return false
//		}
//		lastMsg = m
//	}
//
//	lhs := Pairing(G1ProjectiveOne, s.s)
//	rhs := FQ12One.Copy()
//	for i := range pubKeys {
//		h := HashG2(msgs[i], domain)
//		rhs.MulAssign(Pairing(pubKeys[i].p, h))
//	}
//	return lhs.Equals(rhs)
//}

// VerifyAggregateCommon verifies each public key against a message.
// This is vulnerable to rogue public-key attack. Each user must
// provide a proof-of-knowledge of the public key.
//func (s *Signature) VerifyAggregateCommon(pubKeys []*PublicKey, msg []byte, domain uint64) bool {
//	h := HashG2(msg, domain)
//	lhs := Pairing(G1ProjectiveOne, s.s)
//	rhs := FQ12One.Copy()
//	for _, p := range pubKeys {
//		rhs.MulAssign(Pairing(p.p, h))
//	}
//	return lhs.Equals(rhs)
//}

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
