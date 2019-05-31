package bls_test

import (
	"testing"

	"gitlab.com/nmarley/go-bls-signatures"
)

const Ten = 10

func BenchmarkMillerLoop(b *testing.B) {
	type addData struct {
		p *bls.G1Affine
		q *bls.G2Prepared
	}

	r := NewXORShift(1)
	inData := [Ten]addData{}
	for i := 0; i < Ten; i++ {
		f2, _ := bls.RandG2(r)
		f1, _ := bls.RandG1(r)
		inData[i] = addData{
			q: bls.G2AffineToPrepared(f2.ToAffine()),
			p: f1.ToAffine(),
		}
	}

	b.ResetTimer()

	count := 0
	for i := 0; i < b.N; i++ {
		bls.MillerLoop([]bls.MillerLoopItem{{P: inData[count].p, Q: inData[count].q}})
		count = (count + 1) % Ten
	}
}

func BenchmarkFinalExponentiation(b *testing.B) {
	r := NewXORShift(1)
	inData := [Ten]*bls.FQ12{}
	for i := 0; i < Ten; i++ {
		f2, _ := bls.RandG2(r)
		f1, _ := bls.RandG1(r)
		inData[i] = bls.MillerLoop([]bls.MillerLoopItem{
			{
				Q: bls.G2AffineToPrepared(f2.ToAffine()),
				P: f1.ToAffine(),
			},
		})
	}

	b.ResetTimer()

	count := 0
	for i := 0; i < b.N; i++ {
		bls.FinalExponentiation(inData[count])
		count = (count + 1) % Ten
	}
}

func BenchmarkPairingNew(b *testing.B) {
	type pairingData struct {
		g1 *bls.G1Projective
		g2 *bls.G2Projective
	}
	r := NewXORShift(1)
	inData := [Ten]pairingData{}
	for i := 0; i < Ten; i++ {
		f2, _ := bls.RandG2(r)
		f1, _ := bls.RandG1(r)
		inData[i] = pairingData{g1: f1, g2: f2}
	}

	b.ResetTimer()

	count := 0
	for i := 0; i < b.N; i++ {
		bls.AtePairing(inData[count].g1, inData[count].g2)
		count = (count + 1) % Ten
	}
}

func BenchmarkPairingOld(b *testing.B) {
	type pairingData struct {
		g1 *bls.G1Projective
		g2 *bls.G2Projective
	}
	r := NewXORShift(1)
	inData := [Ten]pairingData{}
	for i := 0; i < Ten; i++ {
		f2, _ := bls.RandG2(r)
		f1, _ := bls.RandG1(r)
		inData[i] = pairingData{g1: f1, g2: f2}
	}

	b.ResetTimer()

	count := 0
	for i := 0; i < b.N; i++ {
		bls.Pairing(inData[count].g1, inData[count].g2)
		count = (count + 1) % Ten
	}
}
