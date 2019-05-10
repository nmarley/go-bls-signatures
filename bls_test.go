package bls_test

import (
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/matryer/is"
	"gitlab.com/nmarley/go-bls-signatures"
)

func SignVerify(loopCount int) error {
	r := NewXORShift(1)
	for i := 0; i < loopCount; i++ {
		priv, _ := bls.RandKey(r)
		pub := bls.PrivToPub(priv)
		msg := []byte(fmt.Sprintf("Hello world! 16 characters %d", i))
		sig := bls.Sign(msg, priv, 0)
		if !bls.Verify(msg, pub, sig, 0) {
			return errors.New("sig did not verify")
		}
	}
	return nil
}

func SignVerifyAggregateCommonMessage(loopCount int) error {
	r := NewXORShift(2)
	pubkeys := make([]*bls.PublicKey, 0, 1000)
	sigs := make([]*bls.Signature, 0, 1000)
	msg := []byte(">16 character identical message")
	for i := 0; i < loopCount; i++ {
		priv, _ := bls.RandKey(r)
		pub := bls.PrivToPub(priv)
		sig := bls.Sign(msg, priv, 0)
		pubkeys = append(pubkeys, pub)
		sigs = append(sigs, sig)
		if i < 10 || i > (loopCount-5) {
			newSig := bls.AggregateSignatures(sigs)
			if !newSig.VerifyAggregateCommon(pubkeys, msg, 0) {
				return errors.New("sig did not verify")
			}
		}
	}
	return nil
}

func SignVerifyAggregateCommonMessageMissingSig(loopCount int) error {
	r := NewXORShift(3)
	skippedSig := loopCount / 2
	pubkeys := make([]*bls.PublicKey, 0, 1000)
	sigs := make([]*bls.Signature, 0, 1000)
	msg := []byte(">16 character identical message")
	for i := 0; i < loopCount; i++ {
		priv, _ := bls.RandKey(r)
		pub := bls.PrivToPub(priv)
		sig := bls.Sign(msg, priv, 0)
		pubkeys = append(pubkeys, pub)
		if i != skippedSig {
			sigs = append(sigs, sig)
		}
		if i < 10 || i > (loopCount-5) {
			newSig := bls.AggregateSignatures(sigs)
			if newSig.VerifyAggregateCommon(pubkeys, msg, 0) != (i < skippedSig) {
				return errors.New("sig did not verify")
			}
		}
	}
	return nil
}

func AggregateSignatures(loopCount int) error {
	r := NewXORShift(4)
	pubkeys := make([]*bls.PublicKey, 0, 1000)
	msgs := make([][]byte, 0, 1000)
	sigs := make([]*bls.Signature, 0, 1000)
	for i := 0; i < loopCount; i++ {
		priv, _ := bls.RandKey(r)
		pub := bls.PrivToPub(priv)
		msg := []byte(fmt.Sprintf(">16 character identical message %d", i))
		sig := bls.Sign(msg, priv, 0)
		pubkeys = append(pubkeys, pub)
		msgs = append(msgs, msg)
		sigs = append(sigs, sig)

		if i < 10 || i > (loopCount-5) {
			newSig := bls.AggregateSignatures(sigs)
			if !newSig.VerifyAggregate(pubkeys, msgs, 0) {
				return errors.New("sig did not verify")
			}
		}
	}
	return nil
}

func TestSignVerify(t *testing.T) {
	err := SignVerify(10)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignVerifyAggregateCommon(t *testing.T) {
	err := SignVerifyAggregateCommonMessage(10)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignVerifyAggregateCommonMissingSig(t *testing.T) {
	err := SignVerifyAggregateCommonMessageMissingSig(10)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignAggregateSigs(t *testing.T) {
	err := AggregateSignatures(10)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAggregateSignaturesDuplicatedMessages(t *testing.T) {
	r := NewXORShift(5)

	pubkeys := make([]*bls.PublicKey, 0, 1000)
	msgs := make([][]byte, 0, 1000)
	sigs := bls.NewAggregateSignature()

	key, _ := bls.RandKey(r)
	pub := bls.PrivToPub(key)
	message := []byte(">16 char first message")
	sig := bls.Sign(message, key, 0)
	pubkeys = append(pubkeys, pub)
	msgs = append(msgs, message)
	sigs.Aggregate(sig)

	if !sigs.VerifyAggregate(pubkeys, msgs, 0) {
		t.Fatal("signature does not verify")
	}

	key2, _ := bls.RandKey(r)
	pub2 := bls.PrivToPub(key2)
	message2 := []byte(">16 char second message")
	sig2 := bls.Sign(message2, key2, 0)
	pubkeys = append(pubkeys, pub2)
	msgs = append(msgs, message2)
	sigs.Aggregate(sig2)

	if !sigs.VerifyAggregate(pubkeys, msgs, 0) {
		t.Fatal("signature does not verify")
	}

	key3, _ := bls.RandKey(r)
	pub3 := bls.PrivToPub(key3)
	sig3 := bls.Sign(message2, key3, 0)
	pubkeys = append(pubkeys, pub3)
	msgs = append(msgs, message2)
	sigs.Aggregate(sig3)

	if sigs.VerifyAggregate(pubkeys, msgs, 0) {
		t.Fatal("signature verifies with duplicate message")
	}
}

func BenchmarkBLSAggregateSignature(b *testing.B) {
	r := NewXORShift(5)
	priv, _ := bls.RandKey(r)
	msg := []byte(fmt.Sprintf(">16 character identical message"))
	sig := bls.Sign(msg, priv, 0)

	s := bls.NewAggregateSignature()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Aggregate(sig)
	}
}

func BenchmarkBLSSign(b *testing.B) {
	r := NewXORShift(5)
	privs := make([]*bls.SecretKey, b.N)
	for i := range privs {
		privs[i], _ = bls.RandKey(r)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {

		msg := []byte(fmt.Sprintf("Hello world! 16 characters %d", i))
		bls.Sign(msg, privs[i], 0)
		// if !bls.Verify(msg, pub, sig) {
		// 	return errors.New("sig did not verify")
		// }
	}
}

func BenchmarkBLSVerify(b *testing.B) {
	r := NewXORShift(5)
	priv, _ := bls.RandKey(r)
	pub := bls.PrivToPub(priv)
	msg := []byte(fmt.Sprintf(">16 character identical message"))
	sig := bls.Sign(msg, priv, 0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bls.Verify(msg, pub, sig, 0)
	}
}

func TestSignatureSerializeDeserialize(t *testing.T) {
	r := NewXORShift(1)
	priv, _ := bls.RandKey(r)
	pub := bls.PrivToPub(priv)
	msg := []byte(fmt.Sprintf(">16 character identical message"))
	sig := bls.Sign(msg, priv, 0)

	if !bls.Verify(msg, pub, sig, 0) {
		t.Fatal("message did not verify before serialization/deserialization")
	}

	sigSer := sig.Serialize(true)
	sigDeser, err := bls.DeserializeSignature(sigSer)
	if err != nil {
		t.Fatal(err)
	}
	if !bls.Verify(msg, pub, sigDeser, 0) {
		t.Fatal("message did not verify after serialization/deserialization")
	}
}

func TestPubkeySerializeDeserialize(t *testing.T) {
	r := NewXORShift(1)
	priv, _ := bls.RandKey(r)
	pub := bls.PrivToPub(priv)
	msg := []byte(fmt.Sprintf(">16 character identical message"))
	sig := bls.Sign(msg, priv, 0)

	if !bls.Verify(msg, pub, sig, 0) {
		t.Fatal("message did not verify before serialization/deserialization of pubkey")
	}

	pubSer := pub.Serialize(true)
	pubDeser, err := bls.DeserializePublicKey(pubSer)
	if err != nil {
		t.Fatal(err)
	}
	if !bls.Verify(msg, pubDeser, sig, 0) {
		t.Fatal("message did not verify after serialization/deserialization of pubkey")
	}
}

func TestSecretkeySerializeDeserialize(t *testing.T) {
	r := NewXORShift(3)
	priv, _ := bls.RandKey(r)
	privSer := priv.Serialize()
	privNew := bls.DeserializeSecretKey(privSer)
	pub := bls.PrivToPub(priv)
	msg := []byte(fmt.Sprintf(">16 character identical message"))
	sig := bls.Sign(msg, privNew, 0)

	if !bls.Verify(msg, pub, sig, 0) {
		t.Fatal("message did not verify before serialization/deserialization of secret")
	}

	pubSer := pub.Serialize(true)
	pubDeser, err := bls.DeserializePublicKey(pubSer)
	if err != nil {
		t.Fatal(err)
	}
	if !bls.Verify(msg, pubDeser, sig, 0) {
		t.Fatal("message did not verify after serialization/deserialization of secret")
	}
}

func TestPubkeySerializeDeserializeBig(t *testing.T) {
	r := NewXORShift(1)
	priv, _ := bls.RandKey(r)
	pub := bls.PrivToPub(priv)
	msg := []byte(fmt.Sprintf(">16 character identical message"))
	sig := bls.Sign(msg, priv, 0)

	if !bls.Verify(msg, pub, sig, 0) {
		t.Fatal("message did not verify before serialization/deserialization of uncompressed pubkey")
	}

	pubSer := pub.Serialize(false)
	pubDeser, _ := bls.DeserializePublicKey(pubSer)
	if !bls.Verify(msg, pubDeser, sig, 0) {
		t.Fatal("message did not verify after serialization/deserialization of uncompressed pubkey")
	}
}

// TODO: Add tests for all test vectors here:
// https://github.com/Chia-Network/bls-signatures/blob/master/SPEC.md

func TestKeygen(t *testing.T) {
	tests := []struct {
		seed          []byte
		secretKey     []byte
		pkFingerprint []byte
	}{
		// keygen([1,2,3,4,5])
		// sk1: 0x022fb42c08c12de3a6af053880199806532e79515f94e83461612101f9412f9e
		// pk1 fingerprint: 0x26d53247

		// keygen([1,2,3,4,5,6])
		//pk2 fingerprint: 0x289bb56e
		{
			seed:          []byte{1, 2, 3, 4, 5},
			secretKey:     sk1,
			pkFingerprint: []byte{0x26, 0xd5, 0x32, 0x47},
		},
		{
			seed:          []byte{1, 2, 3, 4, 5, 6},
			secretKey:     []byte{},
			pkFingerprint: []byte{0x28, 0x9b, 0xb5, 0x6e},
		},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprintf("%d", i), func(st *testing.T) {
			is := is.New(st)

			sk := bls.SecretKeyFromSeed(tt.seed)
			fmt.Printf("%x\n", sk.Serialize())
			if len(tt.secretKey) > 0 {
				is.Equal(sk.Serialize(), tt.secretKey)
			}

			pk := sk.PublicKey()
			is.Equal(pk.Fingerprint(), tt.pkFingerprint)
		})
	}
}

// Implement test for test vector for Signatures#sign
func TestVectorSignaturesSign(t *testing.T) {
	// - [ ] sign([7,8,9], sk1)
	// - [ ] sign([7,8,9], sk2)
	tests := []struct {
		payload     []byte
		secretKey   []byte
		expectedSig []byte
	}{
		{
			payload:     []byte{7, 8, 9},
			secretKey:   sk1,
			expectedSig: sig1,
		},
		//{
		//	payload:     []byte{7, 8, 9},
		//	secretKey:   sk2,
		//	expectedSig: sig2,
		//},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprintf("%d", i), func(st *testing.T) {
			is := is.New(st)

			key := bls.DeserializeSecretKey(tt.secretKey)
			// is.Equal(key.Serialize(), tt.secretKey)

			sig := bls.XSign(tt.payload, key)
			fmt.Printf("%x\n", sig.Serialize(true))

			is.Equal(sig.Serialize(true), tt.expectedSig)
		})
	}
}

// Values either defined in or derived from test vectors and re-used multiple
// times
var sk1 = []byte{
	0x02, 0x2f, 0xb4, 0x2c, 0x08, 0xc1, 0x2d, 0xe3,
	0xa6, 0xaf, 0x05, 0x38, 0x80, 0x19, 0x98, 0x06,
	0x53, 0x2e, 0x79, 0x51, 0x5f, 0x94, 0xe8, 0x34,
	0x61, 0x61, 0x21, 0x01, 0xf9, 0x41, 0x2f, 0x9e,
}
var sk2 = []byte{
	0x50, 0x2c, 0x56, 0x61, 0xf5, 0xaf, 0x46, 0xed,
	0x48, 0xdd, 0xc3, 0xb5, 0x33, 0x2e, 0x21, 0xb9,
	0x3c, 0xc7, 0xd0, 0xa8, 0x4d, 0xf4, 0x6c, 0x4b,
	0x9c, 0x7f, 0xe8, 0xf2, 0x5e, 0xf4, 0x8d, 0x66,
}

var sig1 = []byte{
	0x93, 0xeb, 0x2e, 0x1c, 0xb5, 0xef, 0xcf, 0xb3,
	0x1f, 0x2c, 0x08, 0xb2, 0x35, 0xe8, 0x20, 0x3a,
	0x67, 0x26, 0x5b, 0xc6, 0xa1, 0x3d, 0x9f, 0x0a,
	0xb7, 0x77, 0x27, 0x29, 0x3b, 0x74, 0xa3, 0x57,
	0xff, 0x04, 0x59, 0xac, 0x21, 0x0d, 0xc8, 0x51,
	0xfc, 0xb8, 0xa6, 0x0c, 0xb7, 0xd3, 0x93, 0xa4,
	0x19, 0x91, 0x5c, 0xfc, 0xf8, 0x39, 0x08, 0xdd,
	0xbe, 0xac, 0x32, 0x03, 0x9a, 0xaa, 0x3e, 0x8f,
	0xea, 0x82, 0xef, 0xcb, 0x3b, 0xa4, 0xf7, 0x40,
	0xf2, 0x0c, 0x76, 0xdf, 0x5e, 0x97, 0x10, 0x9b,
	0x57, 0x37, 0x0a, 0xe3, 0x2d, 0x9b, 0x70, 0xd2,
	0x56, 0xa9, 0x89, 0x42, 0xe5, 0x80, 0x60, 0x65,
}
var sig2 = []byte{
	0x97, 0x5b, 0x5d, 0xaa, 0x64, 0xb9, 0x15, 0xbe,
	0x19, 0xb5, 0xac, 0x6d, 0x47, 0xbc, 0x1c, 0x2f,
	0xc8, 0x32, 0xd2, 0xfb, 0x8c, 0xa3, 0xe9, 0x5c,
	0x48, 0x05, 0xd8, 0x21, 0x6f, 0x95, 0xcf, 0x2b,
	0xdb, 0xb3, 0x6c, 0xc2, 0x36, 0x45, 0xf5, 0x20,
	0x40, 0xe3, 0x81, 0x55, 0x07, 0x27, 0xdb, 0x42,
	0x0b, 0x52, 0x3b, 0x57, 0xd4, 0x94, 0x95, 0x9e,
	0x0e, 0x8c, 0x0c, 0x60, 0x60, 0xc4, 0x6c, 0xf1,
	0x73, 0x87, 0x28, 0x97, 0xf1, 0x4d, 0x43, 0xb2,
	0xac, 0x2a, 0xec, 0x52, 0xfc, 0x7b, 0x46, 0xc0,
	0x2c, 0x56, 0x99, 0xff, 0x7a, 0x10, 0xbe, 0xba,
	0x24, 0xd3, 0xce, 0xd4, 0xe8, 0x9c, 0x82, 0x1e,
}

// Custom testing for debugging shit
func TestCustomNGM(t *testing.T) {
	//FQ12OneRoot := bls.NewFQ6(bls.FQ2Zero, bls.FQ2One, bls.FQ2Zero)
	//nwsq := bls.NewFQ12(FQ12OneRoot, bls.FQ6Zero).Inverse()
	//nwcu := bls.NewFQ12(bls.FQ6Zero, FQ12OneRoot).Inverse()
	//
	//x_c0, _ := new(big.Int).SetString("06427044c2270e673490af1756c840361b4090bca24ae94a2f6ad442a5470e94dc6dd392834cf28f3274e85dc2d036e4", 16)
	//x_c1, _ := new(big.Int).SetString("0efe0745224dd9cc23e7d7d63ba7b86ea8deee05b113e02c607afc75f740cb4d0c01d2d361e3fd028b9c24d816afb45a", 16)
	//
	//xVal := bls.NewFQ2(bls.NewFQ(x_c0), bls.NewFQ(x_c1))
	//fmt.Println("NGM(Untwist) xVal:", xVal)
	//
	//// NGM(untwist) point.x: Fq2(Fq(06427044c2270e673490af1756c840361b4090bca24ae94a2f6ad442a5470e94dc6dd392834cf28f3274e85dc2d036e4), Fq(0efe0745224dd9cc23e7d7d63ba7b86ea8deee05b113e02c607afc75f740cb4d0c01d2d361e3fd028b9c24d816afb45a))
	//
	//fmt.Println("NGM(Untwist) ~wsq:", nwsq)
	//fmt.Println("NGM(Untwist) ~wcu:", nwcu)
	//
	//y_c0, _ := new(big.Int).SetString("0b7d5c8331ab2a86a94a97acdd248d828d2f7fefa3429a0637076418882154099f40023d81b1f43f6ae860901ebcbd04", 16)
	//y_c1, _ := new(big.Int).SetString("0a21795e4ad60a5630d919d16421cdcf494ef30f91ebd2c07755ab5493444366e831c16c26bd010d6b87ea6fa59fc428", 16)
	//
	//yVal := bls.NewFQ2(bls.NewFQ(y_c0), bls.NewFQ(y_c1))
	//fmt.Println("NGM(Untwist) yVal:", yVal)
	//
	//x_c0, _ := new(big.Int).SetString("0aa03bc4f23a7419ac3c4376c937fc52620fbf6129af64bb47f2e85c4e43ecf0f437d332f29877c8df08869aecbff59f", 16)
	//x_c1, _ := new(big.Int).SetString("045dcb80301365b277ab945f726fbc1c46cf2ea487647b7118881419a8fcde5c17c9ffa06f4b8539ac939e3d29efbebb", 16)
	//xVal := bls.NewFQ2(bls.NewFQ(x_c0), bls.NewFQ(x_c1))
	//fmt.Println("xVal:", xVal)
	//
	//y_c0, _ := new(big.Int).SetString("0acf6af0be409a6e6d11d8bf20a32da8eb3f397f9a973663572e87b68db2cbb843b8e1d4d4377aa66b38257fe22e4096", 16)
	//y_c1, _ := new(big.Int).SetString("19532057c61556820ee2e8c886ca4cfdc2870514ead9af1c8757f63efc426dd2c324df9603d98666ba4ec4efc3712e3d", 16)
	//yVal := bls.NewFQ2(bls.NewFQ(y_c0), bls.NewFQ(y_c1))
	//fmt.Println("yVal:", yVal)
	//
	//ecks := bls.NewFQ12(
	//	bls.NewFQ6(
	//		bls.FQ2Zero,
	//		bls.FQ2Zero,
	//		xVal,
	//	),
	//	bls.FQ6Zero,
	//)
	//wai := bls.NewFQ12(
	//	bls.FQ6Zero,
	//	bls.NewFQ6(
	//		bls.FQ2Zero,
	//		yVal,
	//		bls.FQ2Zero,
	//	),
	//)
	//fmt.Println("ecks:", ecks)
	//fmt.Println("wai:", wai)

	// tw_x := ecks.FrobeniusMap(1)
	// tw_y := wai.FrobeniusMap(1)
	//fmt.Println("tw_x:", tw_x)
	//fmt.Println("tw_y:", tw_y)

	// newPair := bls.NewFq12Pair(tw_x, tw_y)

	//pts := bls.Twist(tw_x, tw_y)
	// fmt.Println("pts: ", pts)

	// g2pt := bls.NewG2Affine(pts[0], pts[1])
	// fmt.Println("g2pt: ", g2pt)

	// g2pt := bls.Twist(newPair)
	// fmt.Println("g2pt: ", g2pt)

	// return AffinePoint(t2.x[0][0], t2.y[0][0], False, ec)

	// t2 := tw.Twist()
	// fmt.Println("t2:", t2)

	//newY := nwcu.c1.c1.Mul(g.y)

	// == old above this line  ==================================================
	//x_c0, _ := new(big.Int).SetString("09e35c2bcad146e49aa19e4df6699d08f9ccc12d1c7625788f2ada0bad3e5741dc736e2935fe3ebcb0fef6db1166786f", 16)
	//x_c1, _ := new(big.Int).SetString("1245709e2a671d31cbdd537bb3cdcbde39e66511dd390a4a28a0ee0beea98782695d119e2d7ed66ef3f15e6c2a223bf9", 16)
	//xVal := bls.NewFQ2(bls.NewFQ(x_c0), bls.NewFQ(x_c1))
	//// fmt.Println("xVal:", xVal)
	//
	//y_c0, _ := new(big.Int).SetString("1167ad422b392c865d7cbae6adc4f4827a090a6de6c3a9e28f93786e3fc7f516d7dcf8abdbe8df476dda27ba7adb2aad", 16)
	//y_c1, _ := new(big.Int).SetString("0029180da059941e8194ce794161f2b77266d955d61f591dbb177591b6e6d6792454935b388fb769ac91d739491f7110", 16)
	//yVal := bls.NewFQ2(bls.NewFQ(y_c0), bls.NewFQ(y_c1))
	//// fmt.Println("yVal:", yVal)
	//
	//sk, _ := new(big.Int).SetString("22fb42c08c12de3a6af053880199806532e79515f94e83461612101f9412f9e", 16)
	//fmt.Println("sk:", sk)
	//
	//g2 := bls.NewG2Affine(xVal, yVal)
	//fmt.Println("g2:", g2)
	//
	//res := g2.ToProjective().FuckyouMul(sk)
	//fmt.Println("res:", res)

	// == also old above this line  ==================================================

	makeFQ2 := func(c0Hex, c1Hex string) *bls.FQ2 {
		c0, _ := new(big.Int).SetString(c0Hex, 16)
		c1, _ := new(big.Int).SetString(c1Hex, 16)
		return bls.NewFQ2(bls.NewFQ(c0), bls.NewFQ(c1))
	}

	resJacobian := bls.NewG2Projective(
		makeFQ2(
			"07094a722e8bffb9ffe74450ec66cec97df3830907e0c68de204800d44472a6018e008c8a6ced2a79a8b0997dde94424",
			"022f824d1a34a15bf54093cde8bdd0939e4df53551ec4e90ed293faa0a21c8ddd3977a78feefa4c6aaf1d95488471768",
		),
		makeFQ2(
			"0b5a4936ad59c671883f8e8b42ba9596d2447e854c28dbf2b7246f74d7d2ec79918ad6db14bedef2ad2330e0f92bbb74",
			"12b0f954f476fee2793c139ed186e29ccd79515c52d681cb0d9d03d0ba1a20d988bc4f97b331ab89ac6837eeb2db7fab",
		),
		makeFQ2(
			"08ce489a1cf272726fddce17183e3c2d8f9ac956da024105b7f61e3b88def409910df159067dbe8f21b54f74f5b6aaaf",
			"0052301b40b3283d03299cf282c3e56ee4cdb2abac3eb23b762eeb236dcdacf248a926b6711f6ed35923ae72923ee220",
		),
	)
	fmt.Println("NGMgo resJacobian:", resJacobian)

	addEndJacobian := bls.NewG2Projective(
		makeFQ2(
			"0356a2f73692091119cfb08d3914fafab16fdab286022823a8825df932b7db790d9a75a9f5f07f95647e6e1eaad395ac",
			"1527e3c8de0411fc5aeb7f1989fec31d01f8dac358d7e1557b86ab525191fa0b9045df63b963ed856c909fd5acc19861",
		),
		makeFQ2(
			"040e147d2f332d7da1756e51f686428bcad7d1031ee184e5cd937e7a6a1d074e6407ceba6ffd3f356002b7c24403826f",
			"0426112bd6dfb5fc17af15a6e039e5dfe88a69e6958cd20e1ab267d5219436c8089fc662d463b801b2c8b431cac841e5",
		),
		makeFQ2(
			"169659cd2b8245676b7f255ea7c0d91f3b3e22bb87432a49f7334f26694958f73c94e27dce438905a213f06c50422196",
			"09b32a5da729bb31e40c9fe528098e901c24a2885d977dfe9cba268c6cc738cb09a7302aa6c8906d07a1d00e736adc15",
		),
	)
	fmt.Println("NGMgo addEndJacobian:", addEndJacobian)

	res := resJacobian.Add(addEndJacobian)
	fmt.Println("NGMgo finalres:", res)

	jul := resJacobian.OldAdd(addEndJacobian)
	fmt.Println("NGMgo jul:", jul)
}
