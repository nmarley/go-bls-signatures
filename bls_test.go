package bls_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/matryer/is"
	"gitlab.com/nmarley/go-bls-signatures"
)

// TODO: Add tests for all test vectors here:
// https://github.com/Chia-Network/bls-signatures/blob/master/SPEC.md

func TestKeygen(t *testing.T) {
	tests := []struct {
		seed          []byte
		secretKey     []byte
		pkFingerprint uint32
	}{
		// keygen([1,2,3,4,5])
		// sk1: 0x022fb42c08c12de3a6af053880199806532e79515f94e83461612101f9412f9e
		// pk1 fingerprint: 0x26d53247

		// keygen([1,2,3,4,5,6])
		//pk2 fingerprint: 0x289bb56e
		{
			seed:          []byte{1, 2, 3, 4, 5},
			secretKey:     sk1,
			pkFingerprint: 0x26d53247,
		},
		{
			seed:          []byte{1, 2, 3, 4, 5, 6},
			secretKey:     []byte{},
			pkFingerprint: 0x289bb56e,
		},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprintf("%d", i), func(st *testing.T) {
			is := is.New(st)

			sk := bls.SecretKeyFromSeed(tt.seed)
			//fmt.Printf("sk%d: %x\n", i+1, sk.Serialize())
			if len(tt.secretKey) > 0 {
				is.Equal(sk.Serialize(), tt.secretKey)
			}

			pk := sk.PublicKey()
			//fmt.Printf("pk%d: %x\n", i+1, pk.Serialize(true))
			is.Equal(pk.Fingerprint(), tt.pkFingerprint)
		})
	}
}

// Implement test for test vector for Signatures#sign
func TestVectorSignaturesSign(t *testing.T) {
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
		{
			payload:     []byte{7, 8, 9},
			secretKey:   sk2,
			expectedSig: sig2,
		},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprintf("%d", i), func(st *testing.T) {
			is := is.New(st)
			key := bls.DeserializeSecretKey(tt.secretKey)
			sig := bls.Sign(tt.payload, key)
			//fmt.Printf("sig%d: %x\n", i+1, sig.Serialize(true))
			is.Equal(sig.Serialize(true), tt.expectedSig)
		})
	}
}

// Implement test for test vector for Signatures#verify
func TestVectorSignaturesVerify(t *testing.T) {
	tests := []struct {
		payload   []byte
		publicKey []byte
		signature []byte
	}{
		{
			payload:   payload,
			publicKey: pk1,
			signature: sig1,
		},
		{
			payload:   payload,
			publicKey: pk2,
			signature: sig2,
		},
	}
	for i, tt := range tests {
		t.Run(fmt.Sprintf("%d", i), func(st *testing.T) {
			is := is.New(st)
			pk, _ := bls.DeserializePublicKey(tt.publicKey)
			sig, _ := bls.DeserializeSignature(tt.signature)
			is.True(bls.XVerify(tt.payload, pk, sig))
		})
	}
}

// Implement test for test vector for HDKeys
func TestVectorHDKeys(t *testing.T) {
	tests := []struct {
		seed          []byte
		pkFingerprint uint32
		chainCode     string
	}{
		{
			seed:          []byte{1, 50, 6, 244, 24, 199, 1, 25},
			pkFingerprint: 0xa4700b27,
			chainCode:     "d8b12555b4cc5578951e4a7c80031e22019cc0dce168b3ed88115311b8feb1e3",
		},
	}

	hexToInt := func(h string) *big.Int {
		n, _ := new(big.Int).SetString(h, 16)
		return n
	}

	for i, tt := range tests {
		t.Run(fmt.Sprintf("%d", i), func(st *testing.T) {
			is := is.New(st)
			esk := bls.ExtendedSecretKeyFromSeed(tt.seed)
			is.Equal(esk.GetPublicKey().Fingerprint(), tt.pkFingerprint)
			cc := hexToInt(tt.chainCode)
			is.Equal(esk.GetChainCode(), cc)

			esk77 := esk.PrivateChild(77 + (1 << 31))
			is.Equal(esk77.GetPublicKey().Fingerprint(), uint32(0xa8063dcf))

			cc = hexToInt("f2c8e4269bb3e54f8179a5c6976d92ca14c3260dd729981e9d15f53049fd698b")
			is.Equal(esk77.GetChainCode(), cc)

			//fmt.Println("esk77:", esk77)

			fp_3_17 := esk.PrivateChild(3).PrivateChild(17).GetPublicKey().Fingerprint()
			is.Equal(fp_3_17, uint32(0xff26a31f))

			//esk.extendedPublicKey.publicChild(3).publicChild(17).publicKeyFingerprint
			//0xff26a31f

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
var payload = []byte{7, 8, 9}

var pk1 = []byte{
	0x02, 0xa8, 0xd2, 0xaa, 0xa6, 0xa5, 0xe2, 0xe0,
	0x8d, 0x4b, 0x8d, 0x40, 0x6a, 0xaf, 0x01, 0x21,
	0xa2, 0xfc, 0x20, 0x88, 0xed, 0x12, 0x43, 0x1e,
	0x6b, 0x06, 0x63, 0x02, 0x8d, 0xa9, 0xac, 0x59,
	0x22, 0xc9, 0xea, 0x91, 0xcd, 0xe7, 0xdd, 0x74,
	0xb7, 0xd7, 0x95, 0x58, 0x0a, 0xcc, 0x7a, 0x61,
}
var pk2 = []byte{
	0x83, 0xfb, 0xcb, 0xbf, 0xa6, 0xb7, 0xa5, 0xa0,
	0xe7, 0x07, 0xef, 0xaa, 0x9e, 0x6d, 0xe2, 0x58,
	0xa7, 0x9a, 0x59, 0x11, 0x6d, 0xd8, 0x89, 0xce,
	0x74, 0xf1, 0xab, 0x7f, 0x54, 0xc9, 0xb7, 0xba,
	0x15, 0x43, 0x9d, 0xcb, 0x4a, 0xcf, 0xbd, 0xd8,
	0xbc, 0xff, 0xdd, 0x88, 0x25, 0x79, 0x5b, 0x90,
}
