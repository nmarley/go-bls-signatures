package bls_test

import (
	"fmt"
	"math/big"
	"testing"

	"gitlab.com/nmarley/go-bls-signatures"
)

func makeFQ(c0Hex string) *bls.FQ {
	c0, _ := new(big.Int).SetString(c0Hex, 16)
	return bls.NewFQ(c0)
}

func makeFQ2(c0Hex, c1Hex string) *bls.FQ2 {
	c0, _ := new(big.Int).SetString(c0Hex, 16)
	c1, _ := new(big.Int).SetString(c1Hex, 16)
	return bls.NewFQ2(bls.NewFQ(c0), bls.NewFQ(c1))
}

// Custom testing for debugging shit
func TestCustomNGM(t *testing.T) {
	// NGM
	//g1p0 := bls.G1ProjectiveZero.Copy()
	//g1p1 := bls.G1ProjectiveOne.Copy()
	//fmt.Println("NGMgo(custom) g1p0:", g1p0)
	//fmt.Println("NGMgo(custom) g1p1:", g1p1)

	x := makeFQ("02a8d2aaa6a5e2e08d4b8d406aaf0121a2fc2088ed12431e6b0663028da9ac5922c9ea91cde7dd74b7d795580acc7a61")
	y := makeFQ("0145bcfef3c097722ea4994dc043be38a47ca15cf0f7622286ba6f85c4b5ddd412c43042938ab6a2eafcaae38119e305")
	z := makeFQ("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001")

	jp := bls.NewG1Projective(x, y, z)
	fmt.Println("NGMgo(custom) jp:", jp)

	n, _ := new(big.Int).SetString("7429792268441337100724157164307770750544294956256514405682157408702131069250", 10)
	fmt.Println("NGMgo(custom) n:", n)

	res := jp.Mul(n)
	fmt.Println("NGMgo(custom) res:", res)

	//NGMpy(aggpks) addend: JacobianPoint(x=Fq(0x3fbcb..95b90), y=Fq(0x193ac..fcefc), z=Fq(0x1), i=False)
	//NGMpy(aggpks) addend * num: JacobianPoint(x=Fq(0xfeb58..91178), y=Fq(0x5bb54..cc60c), z=Fq(0x1397d..ffcdf), i=False)
}
