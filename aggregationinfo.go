package bls

import (
	"bytes"
	"fmt"
	"math/big"
	"sort"
)

// AggregationInfo ... TODO
type AggregationInfo struct {
	Tree       AggregationTree
	Hashes     []*MessageHash
	PublicKeys []*PublicKey
}

// NewAggregationInfo ... TODO
func NewAggregationInfo(pubKeys []*PublicKey, hashes []*MessageHash) *AggregationInfo {
	return &AggregationInfo{
		PublicKeys: pubKeys,
		Hashes:     hashes,
		Tree:       make(AggregationTree),
	}
}

func (ai AggregationInfo) String() string {
	return fmt.Sprintf(
		"AggregationInfo(Tree: %v, MessageHashes: %v, PublicKeys: %v)",
		ai.Tree,
		ai.Hashes,
		ai.PublicKeys,
	)
}

// Copy performs a deep copy of the AggregationInfo structure
func (ai *AggregationInfo) Copy() *AggregationInfo {
	// Determine size of AI
	size := len(ai.Hashes)

	// Allocate new hashes, publickeys pointer slices
	newMHs := make([]*MessageHash, size)
	newPKs := make([]*PublicKey, size)
	for i := 0; i < size; i++ {
		// the "New" methods should create copies (not return same pointers)
		newMHs[i] = NewMessageHashFromBytes(ai.Hashes[i][:])
		newPKs[i] = NewPublicKey(ai.PublicKeys[i].p)
	}

	// Allocate new AggregationTree and copy entries
	at := make(AggregationTree)
	for k, v := range ai.Tree {
		at[k] = v
	}

	// Return a new copy of this object
	return &AggregationInfo{
		Tree:       at,
		Hashes:     newMHs,
		PublicKeys: newPKs,
	}
}

// MapKeyLen ...
const (
	MessageHashSize = 32
	MapKeyLen       = PublicKeySize + MessageHashSize
)

// MapKey ...
type MapKey [MapKeyLen]byte

// MessageHash represents ... and is required because ...
type MessageHash [MessageHashSize]byte

// String ...
func (mh *MessageHash) String() string {
	return fmt.Sprintf("%064x", *mh)
}

// NewMessageHashFromBytes initializes a new message hash from a byte slice
func NewMessageHashFromBytes(b []byte) *MessageHash {
	mh := &MessageHash{}
	copy(mh[MessageHashSize-len(b):], b)
	return mh
}

// NewMapKey ... TODO
func NewMapKey(pk *PublicKey, mh *MessageHash) MapKey {
	var mk MapKey
	copy(mk[:], mh[:])
	pubkeyBytes := pk.Serialize()
	copy(mk[MapKeyLen-len(pubkeyBytes):], pubkeyBytes)
	return mk
}

// Split "deserializes" a message hash / public key entry and returns the results
func (mk *MapKey) Split() (*PublicKey, *MessageHash) {
	var mh MessageHash
	copy(mh[0:MessageHashSize], mk[0:MessageHashSize])

	pk, _ := DeserializePublicKey(mk[MessageHashSize:MapKeyLen])

	return pk, &mh
}

// String
func (mk *MapKey) String() string {
	pk, mh := mk.Split()
	pk.StringShort()
	return fmt.Sprintf("PK(%s),MH(%s)", pk.StringShort(), mh)
}

// AggregationInfoFromMsgHash ...
func AggregationInfoFromMsgHash(pk *PublicKey, mh *MessageHash) *AggregationInfo {
	// Public key len + Message hash len (sha256 hash = 32 bytes)
	var mk MapKey

	// Copy hash bytes to mapkey
	copy(mk[MessageHashSize-len(mh):], mh[:])

	// Serialize public key to raw bytes
	pubkeyBytes := pk.Serialize()

	// Now copy serialized public key bytes into mapkey, located just after the message hash
	copy(mk[MapKeyLen-len(pubkeyBytes):], pubkeyBytes)

	ai := NewAggregationInfo([]*PublicKey{pk}, []*MessageHash{mh})
	ai.Tree[mk] = bigOne

	return ai
}

// TODO: Tighter rules around access to tree & re-shuffling of pubkeys / hashes
// Tree should not ever have invalid info

// AggregationTree ...
type AggregationTree map[MapKey]*big.Int

// Empty ...
func (at *AggregationTree) Empty() bool {
	return len(*at) == 0
}

// String ... this is actually just for debugging, so can be dropped later.
// Don't waste time optimizing.
func (at AggregationTree) String() string {
	bigStr := "AI Tree:"
	//count := 0
	for k, v := range at {
		//if count != 0 {
		//	bigStr += ","
		//}

		entryStr := fmt.Sprintf("\n\tMapKey=%v,Exponent=%v", k.String(), v.String())
		bigStr += entryStr

		//count++
	}
	return bigStr
}

// Less compares two aggregation infos by the following process:
// (A.msgHash || A.pk || A.exponent) < (B.msgHash || B.pk || B.exponent)
// for each element in their trees
func (ai *AggregationInfo) Less(other *AggregationInfo) bool {
	if ai.Tree.Empty() && other.Tree.Empty() {
		return false
	}

	lessThan := false
	for i := 0; i < len(ai.Hashes) || i < len(other.Hashes); i++ {
		// If we run out of elements, return
		if len(ai.Hashes) == i {
			lessThan = true
			break
		}
		if len(other.Hashes) == i {
			lessThan = false
			break
		}
		// Otherwise, compare the elements
		bufA := NewMapKey(ai.PublicKeys[i], ai.Hashes[i])
		bufB := NewMapKey(other.PublicKeys[i], other.Hashes[i])
		compare := bytes.Compare(bufA[:], bufB[:])
		if compare < 0 {
			lessThan = true
			break
		} else if compare > 0 {
			lessThan = false
			break
		}
		// If they are equal, compare the exponents
		aExp, _ := ai.Tree[bufA]
		bExp, _ := other.Tree[bufB]
		compare = aExp.Cmp(bExp)
		if compare < 0 {
			lessThan = true
			break
		} else if compare > 0 {
			lessThan = false
			break
		}
	}
	// If all comparisons are equal, return false
	return lessThan
}

// MergeAggregationInfos ...
func MergeAggregationInfos(aggInfos []*AggregationInfo) *AggregationInfo {
	messages := NewMessageSet()
	collidingMessages := NewMessageSet()

	for _, ai := range aggInfos {
		// TODO: Add nil check here (prevents panic)
		//       Maybe just continue instead of err
		messagesLocal := NewMessageSet()
		for k := range ai.Tree {
			_, mh := k.Split()
			if messages.HasMsg(mh) && !messagesLocal.HasMsg(mh) {
				collidingMessages.AddMsg(mh)
			}
			messages.AddMsg(mh)
			messagesLocal.AddMsg(mh)
		}
	}

	if collidingMessages.Len() == 0 {
		return SimpleMergeAggregationInfos(aggInfos)
	}

	collidingInfos := []*AggregationInfo{}
	nonCollidingInfos := []*AggregationInfo{}

	for _, ai := range aggInfos {
		infoCollides := false
		for k := range ai.Tree {
			_, mh := k.Split()
			if collidingMessages.HasMsg(mh) {
				infoCollides = true
				collidingInfos = append(collidingInfos, ai)
				break
			}
		}
		if !infoCollides {
			nonCollidingInfos = append(nonCollidingInfos, ai)
		}
	}

	combined := SecureMergeAggregationInfos(collidingInfos)
	nonCollidingInfos = append(nonCollidingInfos, combined)

	return SimpleMergeAggregationInfos(nonCollidingInfos)
}

// SimpleMergeAggregationInfos ...
//
// Infos are just merged together with no addition of exponents, since they are
// disjoint
func SimpleMergeAggregationInfos(aggInfos []*AggregationInfo) *AggregationInfo {
	newTree := make(AggregationTree)
	for _, ai := range aggInfos {
		for k, v := range ai.Tree {
			newTree[k] = v
		}
	}

	sortedMapKeys := make([]MapKey, len(newTree))
	i := 0
	for k := range newTree {
		sortedMapKeys[i] = k
		i++
	}

	// Sort lexicographically binary, then split out pks / hashes
	sort.Sort(By(sortedMapKeys))

	// message_hashes = [message_hash for (message_hash, public_key) in mh_pubkeys]
	// public_keys = [public_key for (message_hash, public_key) in mh_pubkeys]
	messageHashes := make([]*MessageHash, len(sortedMapKeys))
	pubKeys := make([]*PublicKey, len(sortedMapKeys))
	for i, mk := range sortedMapKeys {
		pk, mh := mk.Split()
		messageHashes[i] = mh
		pubKeys[i] = pk
	}

	return &AggregationInfo{
		Tree:       newTree,
		Hashes:     messageHashes,
		PublicKeys: pubKeys,
	}
}

// SecureMergeAggregationInfos ...
//
// Infos are merged together with combination of exponents
func SecureMergeAggregationInfos(collidingInfos []*AggregationInfo) *AggregationInfo {
	// Groups are sorted by message then pk then exponent
	// Each info object (and all of it's exponents) will be
	// exponentiated by one of the Ts

	// Sort AIs
	sort.Sort(ByAI(collidingInfos))

	total := 0
	for _, ai := range collidingInfos {
		total += len(ai.Tree)
	}

	sortedMapKeys := make([]MapKey, total)
	count := 0
	for _, ai := range collidingInfos {
		for k := range ai.Tree {
			sortedMapKeys[count] = k
			count++
		}
	}

	// Sort lexicographically binary, then split out pks / hashes
	sort.Sort(By(sortedMapKeys))
	publicKeys := make([]*PublicKey, len(sortedMapKeys))
	for i, mk := range sortedMapKeys {
		pk, _ := mk.Split()
		publicKeys[i] = pk
	}

	computedTs := HashPKs(len(collidingInfos), publicKeys)

	// Group order, exponents can be reduced mod the order
	// order := RFieldModulus

	newTree := make(AggregationTree)
	for i := 0; i < len(collidingInfos); i++ {
		for k, v := range collidingInfos[i].Tree {

			// TODO: REFACTOR. Esp. like the new(big.Int).Mul(v, computedTs[i])
			// can be extracted for both conditions

			newVal, found := newTree[k]
			if !found {
				// This message & pk have not been included yet
				newExp := new(big.Int).Mul(v, computedTs[i])
				newExp.Mod(newExp, RFieldModulus)
				newTree[k] = newExp
			} else {
				// This message and pk are already included, so multiply
				addEnd := new(big.Int).Mul(v, computedTs[i])
				addEnd.Add(addEnd, newVal)
				addEnd.Mod(addEnd, RFieldModulus)
				newTree[k] = addEnd
			}
		}
	}

	sortedMapKeys2 := make([]MapKey, len(newTree))
	i := 0
	for k := range newTree {
		sortedMapKeys2[i] = k
		i++
	}

	// Sort lexicographically binary, then split out pks / hashes
	sort.Sort(By(sortedMapKeys2))

	messageHashes := make([]*MessageHash, len(sortedMapKeys2))
	pubKeys := make([]*PublicKey, len(sortedMapKeys2))
	for i, mk := range sortedMapKeys2 {
		pk, mh := mk.Split()
		messageHashes[i] = mh
		pubKeys[i] = pk
	}

	return &AggregationInfo{
		Tree:       newTree,
		Hashes:     messageHashes,
		PublicKeys: pubKeys,
	}
}

// ByAI implements sort.Interface for []*AggregationInfo
type ByAI []*AggregationInfo

func (s ByAI) Len() int           { return len(s) }
func (s ByAI) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s ByAI) Less(i, j int) bool { return s[i].Less(s[j]) }

// Nothing ... does nothing.
func Nothing() {}
