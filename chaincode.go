package chiabls

import (
	"math/big"
)

// ChainCodeSize is the size in bytes of a serialized chain code.
const ChainCodeSize = 32

// ChainCode is used in extended keys to derive child keys.
type ChainCode struct {
	n *big.Int
}

// ChainCodeFromBytes constructs a chain code from bytes.
func ChainCodeFromBytes(data []byte) ChainCode {
	return ChainCode{
		n: new(big.Int).SetBytes(data),
	}
}

// Serialize returns the serialized byte representation of the ChainCode object.
func (cc ChainCode) Serialize() []byte {
	bytes := cc.n.Bytes()
	var buf [ChainCodeSize]byte
	copy(buf[ChainCodeSize-len(bytes):], bytes)
	return buf[:]
}

// Equal tests if one ChainCode object is equal to another.
func (cc ChainCode) Equal(other ChainCode) bool {
	return cc.n.Cmp(other.n) == 0
}
