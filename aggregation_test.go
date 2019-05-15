package bls_test

import (
	"fmt"
	"testing"

	"github.com/matryer/is"
	"gitlab.com/nmarley/go-bls-signatures"
)

// TODO: use strings, not bytes here (use serialize/deserialize methods)
func TestVectorAggregation(t *testing.T) {
	tests := []struct {
		sigs        [][]byte
		pubkeys     [][]byte
		payloads    [][]byte
		expectedSig string
	}{
		{
			sigs:        [][]byte{sig1, sig2},
			pubkeys:     [][]byte{pk1, pk2},
			payloads:    [][]byte{payload, payload},
			expectedSig: "0a638495c1403b25be391ed44c0ab013390026b5892c796a85ede46310ff7d0e0671f86ebe0e8f56bee80f28eb6d999c0a418c5fc52debac8fc338784cd32b76338d629dc2b4045a5833a357809795ef55ee3e9bee532edfc1d9c443bf5bc658",
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
			aggSig := bls.AggregateSignatures(sigs)

			// Aggregate(sig1, sig2)
			// fmt.Printf("NGMgo(test) aggSig: %x\n", aggSig.Serialize())
			is.Equal(fmt.Sprintf("%096x", aggSig.Serialize()), tt.expectedSig)

			//bls.Verify()
			//verify(aggSig2, mergeInfos(sig1.aggInfo, sig2.aggInfo))
			//true

			// sig3 = sk1.sign(bytes([1, 2, 3]))
			// sig4 = sk1.sign(bytes([1, 2, 3, 4]))
			// sig5 = sk2.sign(bytes([1, 2]))

			// TODO: Rename
			sk1o := bls.DeserializeSecretKey(sk1)
			sk2o := bls.DeserializeSecretKey(sk2)

			// TODO: Define sign on SecretKey obj...
			sig3 := sk1o.Sign([]byte{1, 2, 3})
			sig4 := sk1o.Sign([]byte{1, 2, 3, 4})
			sig5 := sk2o.Sign([]byte{1, 2})

			// TODO: Define verify on signature obj...
			aggSig2 := bls.AggregateSignatures([]*bls.Signature{sig3, sig4, sig5})
			//aggSig2.Verify()  // true || false
			is.Equal(fmt.Sprintf("%096x", aggSig2.Serialize()), "8b11daf73cd05f2fe27809b74a7b4c65b1bb79cc1066bdf839d96b97e073c1a635d2ec048e0801b4a208118fdbbb63a516bab8755cc8d850862eeaa099540cd83621ff9db97b4ada857ef54c50715486217bd2ecb4517e05ab49380c041e159b")

		})
	}
}
