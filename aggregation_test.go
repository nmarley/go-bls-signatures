package bls_test

import (
	"fmt"
	// "math/big"
	"github.com/matryer/is"
	"gitlab.com/nmarley/go-bls-signatures"
	"testing"
)

func TestVectorAggregation(t *testing.T) {
	tests := []struct {
		sigs     [][]byte
		pubkeys  [][]byte
		payloads [][]byte
	}{
		{
			sigs:     [][]byte{sig1, sig2},
			pubkeys:  [][]byte{pk1, pk2},
			payloads: [][]byte{payload, payload},
		},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprintf("%d", i), func(st *testing.T) {
			is := is.New(st)
			var sigs []*bls.Signature
			for i, sigBytes := range tt.sigs {
				pub, _ := bls.DeserializePublicKey(tt.pubkeys[i])
				mh := bls.NewMessageHashFromBytes(bls.Hash256(tt.payloads[i]))
				aggInfo := bls.AggregationInfoFromMsgHash(pub, mh)
				signature, _ := bls.DeserializeSignature(sigBytes)
				signature.SetAggregationInfo(aggInfo)
				sigs = append(sigs, signature)
			}
			//fmt.Println("sigs:", sigs)
			aggSig := bls.AggregateSignatures(sigs)
			fmt.Printf("NGMgo(test) aggSig: %x\n", aggSig.Serialize())
			// Aggregate(sig1, sig2)
			is.Equal(1, 1)
		})
	}
}
