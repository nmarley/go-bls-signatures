package bls

import (
	"bytes"
	"encoding/binary"
	"math/big"
)

// Sizes of g1/g2 elements
// TODO: Probably move these somewhere else...
const (
	G1ElementSize = 48
	G2ElementSize = 96
)

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
