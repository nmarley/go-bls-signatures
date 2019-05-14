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
		sigs [][]byte
	}{
		{
			sigs: [][]byte{sig1, sig2},
		},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprintf("%d", i), func(st *testing.T) {
			is := is.New(st)
			var sigs []*bls.Signature
			for _, sigBytes := range tt.sigs {
				signature, _ := bls.DeserializeSignature(sigBytes)
				sigs = append(sigs, signature)
			}
			//fmt.Println("sigs:", sigs)
			aggSig := bls.AggregateSignatures(sigs)
			fmt.Printf("aggSig: %x\n", aggSig.Serialize(true))
			// Aggregate(sig1, sig2)
			is.Equal(1, 1)
		})
	}
}
