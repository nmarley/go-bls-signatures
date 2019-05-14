package bls

import (
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
