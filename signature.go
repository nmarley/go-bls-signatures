package bls

import (
	"fmt"
	"math/big"
	"sort"
)

// ...
const (
	SignatureSize = G2ElementSize
)

// Signature is a message signature
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

// GetAggregationInnfo TEMP method to get AI for debugging...
func (s *Signature) GetAggregationInfo() *AggregationInfo {
	return s.ai
}

// Debug ... TEMP method
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

// Verify verifies a signature against a message and a public key.
//
// This implementation of verify has several steps. First, it reorganizes the
// pubkeys and messages into groups, where each group corresponds to a message.
// Then, it checks if the signature has info on how it was aggregated. If so,
// we exponentiate each pk based on the exponent in the AggregationInfo. If
// not, we find public keys that share messages with others, and aggregate all
// of these securely (with exponents). Finally, since each public key now
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

// AggregateSignatures aggregates many signatures aggregates many signatures on
// messages, some of which may be identical, using a combination of simple and
// secure aggregation. Signatures are grouped based on which ones share common
// messages, and these are all merged securely. The returned signature contains
// information on how the aggregation was done (AggragationInfo).
func AggregateSignatures(signatures []*Signature) *Signature {
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

	// Add non-colliding signatures...
	for _, sig := range nonCollidingSigs {
		aggSig = aggSig.Add(sig.s)
	}

	// Create final aggregation info
	aggInfos := make([]*AggregationInfo, len(signatures))
	for i, sig := range signatures {
		aggInfos[i] = sig.ai
	}
	finalAggInfo := MergeAggregationInfos(aggInfos)

	finalSig := NewSignature(aggSig, finalAggInfo)

	return finalSig
}

// SigsByAI implements sort.Interface for []*Signature, and sorts by
// AggregationInfo
type SigsByAI []*Signature

func (s SigsByAI) Len() int           { return len(s) }
func (s SigsByAI) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s SigsByAI) Less(i, j int) bool { return s[i].ai.Less(s[j].ai) }

// String implements the Stringer interface
func (s Signature) String() string {
	return fmt.Sprintf("%096x", s.Serialize())
}

// DebugGetPoint ...
func (s *Signature) DebugGetPoint() *G2Projective {
	return s.s
}

// Signature division

// DivideBy divides the aggregate signature by a list of signatures. These
// divisors can be single or aggregate signatures, but all msg/pk pairs in
// these signatures must be distinct and unique.
//
// Signature division (elliptic curve subtraction). This is useful if you have
// already verified parts of the tree, since verification of the resulting
// quotient signature will be faster (less pairings have to be perfomed).
//
// This function Divides an aggregate signature by other signatures in the
// aggregate trees. A signature can only be divided if it is part of the
// subset, and all message/public key pairs in the aggregationInfo for the
// divisor signature are unique. i.e you cannot divide s1 / s2, if s2 is an
// aggregate signature containing m1,pk1, which is also present somewhere else
// in s1's tree. Note, s2 itself does not have to be unique.
func (s *Signature) DivideBy(signatures []*Signature) *Signature {
	if len(signatures) == 0 {
		return NewSignature(s.s, s.ai)
	}

	// TODO: Calculate max first & reduce allocations... remove appends() where
	// possible
	messageHashesToRemove := []*MessageHash{}
	pubKeysToRemove := []*PublicKey{}

	prod := NewG2Projective(FQ2One, FQ2One, FQ2Zero)

	for _, sig := range signatures {
		pks := sig.ai.PublicKeys
		mhs := sig.ai.Hashes
		if len(pks) != len(mhs) {
			// TODO: Don't panic
			panic("invalid aggregation info!")
		}
		var quotient *FQ
		for i, pk := range pks {
			mk := NewMapKey(pk, mhs[i])
			divisor := sig.ai.Tree[mk]

			// err if this key doesn't exist in s.ai.Tree
			dividend, found := s.ai.Tree[mk]
			if !found {
				panic("Signature is not a subset")
			}

			// TODO: This is some screwy logic. There's a lot better way to do
			// ensure unique MapKeys than this.

			if i == 0 {
				quotient = NewFQ(dividend).Div(NewFQ(divisor))
				//quotient = NewFQ(new(big.Int).Div(dividend, divisor))
			} else {
				// Makes sure the quotient is identical for each public key,
				// which means message/pk pair is unique
				newQuotient := NewFQ(dividend).Div(NewFQ(divisor))
				if quotient != newQuotient {
					// TODO: Don't panic
					panic("Cannot divide by aggregate signature, msg/pk pairs are not unique")
				}
			}
			// TODO: do not append, reduce allocations
			messageHashesToRemove = append(messageHashesToRemove, mhs[i])
			pubKeysToRemove = append(pubKeysToRemove, pk)
		}
		prod = prod.Add(sig.s.Mul(quotient.Neg().n))
	}

	// TODO: Deep copy?
	copy := NewSignature(s.s.Add(prod), s.ai)

	// TODO: is this really needed? Why not tree.RemoveMK(mk) above and save
	// all these wasted cycles?

	// Remove all the "to remove" entries from copy AI Tree
	for i, mh := range messageHashesToRemove {
		a := mh
		b := pubKeysToRemove[i]
		mk := NewMapKey(b, a)
		_, ok := copy.ai.Tree[mk]
		if ok {
			delete(copy.ai.Tree, mk)
		}
	}

	sortedMapKeys := make([]MapKey, len(copy.ai.Tree))
	i := 0
	for k, _ := range copy.ai.Tree {
		sortedMapKeys[i] = k
		i++
	}

	// Sort lexicographically binary, then split out pks / hashes
	sort.Sort(By(sortedMapKeys))
	sortedMHs := make([]*MessageHash, len(sortedMapKeys))
	sortedPKs := make([]*PublicKey, len(sortedMapKeys))
	for i = 0; i < len(sortedMapKeys); i++ {
		mk := sortedMapKeys[i]
		pk, mh := mk.Split()
		sortedMHs[i] = mh
		sortedPKs[i] = pk
	}

	// Sorted AI
	ai := NewAggregationInfo(sortedPKs, sortedMHs)
	copy.ai = ai

	return copy
}
