package bls

import (
	"math/big"
)

// AggregationInfo ...
type AggregationInfo struct {
	// probably ptr?
	Tree XAggregationTree

	// ptr?
	Hashes [][]byte

	// ptr?
	PublicKeys []PublicKey
}

func NewAggregationInfo() *AggregationInfo {
	return &AggregationInfo{
		Tree: make(XAggregationTree),
	}
}

func AggregationInfoFromMsgHash(pk *PublicKey, h []byte) *AggregationInfo {
	// 32 bytes for the message hash (sha256 hash)
	//buf := make([]byte, PublicKeySize+32)

	//pubkeyBytes := pk.Serialize(true)
	//copy(buf, pubkeyBytes)
	//fmt.Println("NGMgo buf:", buf)

	ai := NewAggregationInfo()
	// ai.Tree[]

	return ai
}

// AggregationTree ...
type XAggregationTree map[uint8]*big.Int

// probably just make this a custom map TBH...
type AggregationTree struct {
	// x map[uint8]*big.Int
}
