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
	g1p0 := bls.G1ProjectiveZero.Copy()
	g1p1 := bls.G1ProjectiveOne.Copy()
	fmt.Println("NGMgo(custom) g1p0:", g1p0)
	fmt.Println("NGMgo(custom) g1p1:", g1p1)
}
