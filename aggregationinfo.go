package bls

import (
	"math/big"
)

// AggregationInfo ...
type AggregationInfo struct {
	Tree       AggregationTree
	Hashes     [][]byte
	PublicKeys []*PublicKey
}

func NewAggregationInfo(pubKeys []*PublicKey, hashes [][]byte) *AggregationInfo {
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

func NewMapKey(pk *PublicKey, mh MessageHash) MapKey {
	var mk MapKey
	copy(mk[:], mh[:])
	pubkeyBytes := pk.Serialize(true)
	copy(mk[MapKeyLen-len(pubkeyBytes):], pubkeyBytes)
	return mk
}

func AggregationInfoFromMsgHash(pk *PublicKey, h []byte) *AggregationInfo {
	// Public key length + 32 bytes for the message hash (sha256 hash)
	var mk MapKey

	// Copy hash bytes to mapkey
	copy(mk[MessageHashSize-len(h):], h)

	// Serialize public key to raw bytes
	pubkeyBytes := pk.Serialize(true)

	// Now copy serialized public key bytes into mapkey, located just after the message hash
	copy(mk[MapKeyLen-len(pubkeyBytes):], pubkeyBytes)

	ai := NewAggregationInfo([]*PublicKey{pk}, [][]byte{h})
	ai.Tree[mk] = bigOne

	return ai
}

// AggregationTree ...
type AggregationTree map[MapKey]*big.Int

// GetPublicKeys
func (ai *AggregationInfo) GetPublicKeys() []*PublicKey {
	return ai.PublicKeys
}

// GetMessageHashes
func (ai *AggregationInfo) GetMessageHashes() [][]byte {
	return ai.Hashes
}
