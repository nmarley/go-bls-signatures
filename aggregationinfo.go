package bls

import (
	"bytes"
	"fmt"
	"math/big"
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

// MapKeyLen ...
const (
	MessageHashSize = 32
	MapKeyLen       = PublicKeySize + MessageHashSize
)

// MapKey ...
type MapKey [MapKeyLen]byte

// MessageHash represents ... and is required because ...
type MessageHash [MessageHashSize]byte

// String
func (mh *MessageHash) String() string {
	return fmt.Sprintf("%064x", *mh)
}

// NewMessageHash initializes a new message hash from a byte slice
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

// AggregationTree ...
type AggregationTree map[MapKey]*big.Int

// Empty
func (at *AggregationTree) Empty() bool {
	return len(*at) == 0
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
	return &AggregationInfo{}
}
