package bls_test

import (
	// "fmt"
	"testing"

	// "github.com/matryer/is"
	"gitlab.com/nmarley/go-bls-signatures"
)

// Custom testing for debugging shit
func TestCustomNGM(t *testing.T) {
	//makeFQ2 := func(c0Hex, c1Hex string) *bls.FQ2 {
	//	c0, _ := new(big.Int).SetString(c0Hex, 16)
	//	c1, _ := new(big.Int).SetString(c1Hex, 16)
	//	return bls.NewFQ2(bls.NewFQ(c0), bls.NewFQ(c1))
	//}

	// NGM
	//
	//fmt.Println(pk1)
	//
	//pubkey, err := bls.DeserializePublicKey(pk1)
	//if err != nil {
	//	panic(err)
	//}
	//
	//h := bls.Hash256(payload)
	//fmt.Println("h =", h)
	//
	//aggInfo := bls.AggregationInfoFromMsgHash(pubkey, h)
	//fmt.Println("aggInfo =", aggInfo)

	// big7 := big.NewInt(7)
	// big8 := big.NewInt(8)

	// seven := bls.IntToBits(big7)
	// eight := bls.IntToBits(big8)

	// fmt.Println("seven:", seven)
	// fmt.Println("eight:", eight)

	makeFQ := func(c0Hex string) *bls.FQ {
		c0, _ := new(big.Int).SetString(c0Hex, 16)
		return bls.NewFQ(c0)
	}

	makeFQ2 := func(c0Hex, c1Hex string) *bls.FQ2 {
		c0, _ := new(big.Int).SetString(c0Hex, 16)
		c1, _ := new(big.Int).SetString(c1Hex, 16)
		return bls.NewFQ2(bls.NewFQ(c0), bls.NewFQ(c1))
	}

	//x := makeFQ("02a8d2aaa6a5e2e08d4b8d406aaf0121a2fc2088ed12431e6b0663028da9ac5922c9ea91cde7dd74b7d795580acc7a61")
	//y := makeFQ("0145bcfef3c097722ea4994dc043be38a47ca15cf0f7622286ba6f85c4b5ddd412c43042938ab6a2eafcaae38119e305")
	//z := bls.FQOne.Copy()
	//g1p := bls.NewG1Projective(x, y, z)
	//fmt.Println("NGMgo g1p: ", g1p)
	//
	//dbl := g1p.Double()
	//fmt.Println("NGMgo dbl: ", dbl)
}
