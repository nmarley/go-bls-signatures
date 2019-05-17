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
			sigs:        [][]byte{sig1Bytes, sig2Bytes},
			pubkeys:     [][]byte{pk1Bytes, pk2Bytes},
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
			is.Equal(fmt.Sprintf("%096x", aggSig.Serialize()), tt.expectedSig)

			// TODO: Rename variables... sk1 => sk1Bytes, sk1o => sk1
			sk1o := bls.DeserializeSecretKey(sk1Bytes)
			sk2o := bls.DeserializeSecretKey(sk2Bytes)

			sig3 := sk1o.Sign([]byte{1, 2, 3})
			sig4 := sk1o.Sign([]byte{1, 2, 3, 4})
			sig5 := sk2o.Sign([]byte{1, 2})

			aggSig2 := bls.AggregateSignatures([]*bls.Signature{sig3, sig4, sig5})
			is.Equal(fmt.Sprintf("%096x", aggSig2.Serialize()), "8b11daf73cd05f2fe27809b74a7b4c65b1bb79cc1066bdf839d96b97e073c1a635d2ec048e0801b4a208118fdbbb63a516bab8755cc8d850862eeaa099540cd83621ff9db97b4ada857ef54c50715486217bd2ecb4517e05ab49380c041e159b")
			is.True(aggSig2.Verify())

			// TODO: optimize this or just drop table-driven tests and do what the python one does...
			sig1, _ := bls.DeserializeSignature(sig1Bytes)
			sig2, _ := bls.DeserializeSignature(sig2Bytes)
			pk1, _ := bls.DeserializePublicKey(pk1Bytes)
			pk2, _ := bls.DeserializePublicKey(pk2Bytes)

			mh := bls.NewMessageHashFromBytes(bls.Hash256(payload))
			sig1.SetAggregationInfo(bls.AggregationInfoFromMsgHash(pk1, mh))
			sig2.SetAggregationInfo(bls.AggregationInfoFromMsgHash(pk2, mh))

			aggPk := bls.AggregatePublicKeys([]*bls.PublicKey{pk1, pk2}, true)
			//fmt.Println("NGMgo(aggTest) aggPk:", aggPk)
			is.Equal(fmt.Sprintf("%x", aggPk.Serialize()), "13ff74ea55952924e824c5a08825e3c36d928df7fba15bf492d00a6a112868625f772c9102f2d9e21b99bf99fdc627b6")

			toMergeAIs := []*bls.AggregationInfo{sig1.GetAggregationInfo(), sig2.GetAggregationInfo()}
			//fmt.Println("NGMgo(aggTest) toMergeAIs:", toMergeAIs)

			ai := bls.MergeAggregationInfos(toMergeAIs)
			aggSig2.SetAggregationInfo(ai)
			is.True(aggSig.Verify())

			//aggPk2, _ := bls.DeserializePublicKey(pk2Bytes)
			mh = bls.NewMessageHashFromBytes([]byte{7, 8, 9})
			ai = bls.AggregationInfoFromMsgHash(pk2, mh)
			sig1.SetAggregationInfo(ai)
			is.Equal(sig1.Verify(), false)

			toMergeAIs = []*bls.AggregationInfo{
				sig3.GetAggregationInfo(),
				sig4.GetAggregationInfo(),
				sig5.GetAggregationInfo(),
			}
			aggSig2.SetAggregationInfo(bls.MergeAggregationInfos(toMergeAIs))
			is.True(aggSig2.Verify())
		})
	}
}

// TODO: use strings, not bytes here (use serialize/deserialize methods)
func TestVectorAggregation2(t *testing.T) {
	is := is.New(t)

	m1 := []byte{1, 2, 3, 40}
	m2 := []byte{5, 6, 70, 201}
	m3 := []byte{9, 10, 11, 12, 13}
	m4 := []byte{15, 63, 244, 92, 0, 1}

	sk1 := bls.SecretKeyFromSeed([]byte{1, 2, 3, 4, 5})
	sk2 := bls.SecretKeyFromSeed([]byte{1, 2, 3, 4, 5, 6})

	sig1 := sk1.Sign(m1)
	sig2 := sk2.Sign(m2)
	sig3 := sk2.Sign(m1)
	sig4 := sk1.Sign(m3)
	sig5 := sk1.Sign(m1)
	sig6 := sk1.Sign(m4)

	sigL := bls.AggregateSignatures([]*bls.Signature{sig1, sig2})
	sigR := bls.AggregateSignatures([]*bls.Signature{sig3, sig4, sig5})

	is.True(sigL.Verify())
	is.True(sigR.Verify())

	sigFinal := bls.AggregateSignatures([]*bls.Signature{sigL, sigR, sig6})
	is.Equal(fmt.Sprintf("%096x", sigFinal.Serialize()), "07969958fbf82e65bd13ba0749990764cac81cf10d923af9fdd2723f1e3910c3fdb874a67f9d511bb7e4920f8c01232b12e2fb5e64a7c2d177a475dab5c3729ca1f580301ccdef809c57a8846890265d195b694fa414a2a3aa55c32837fddd80")
	is.True(sigFinal.Verify())

	// begin division...

	// ### Signature division
	// * divide(sigFinal, [sig2, sig5, sig6])
	//   * quotient: 0x8ebc8a73a2291e689ce51769ff87e517be6089fd0627b2ce3cd2f0ee1ce134b39c4da40928954175014e9bbe623d845d0bdba8bfd2a85af9507ddf145579480132b676f027381314d983a63842fcc7bf5c8c088461e3ebb04dcf86b431d6238f

	// sigFinal, [sig2, sig5, sig6]
	quotient := sigFinal.DivideBy([]*bls.Signature{sig2, sig5, sig6})
	is.Equal(fmt.Sprintf("%096x", quotient.Serialize()), "8ebc8a73a2291e689ce51769ff87e517be6089fd0627b2ce3cd2f0ee1ce134b39c4da40928954175014e9bbe623d845d0bdba8bfd2a85af9507ddf145579480132b676f027381314d983a63842fcc7bf5c8c088461e3ebb04dcf86b431d6238f")
}
