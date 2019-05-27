package bls_test

import (
	"bytes"
	"fmt"
	//"fmt"
	"testing"

	"gitlab.com/nmarley/go-bls-signatures"
)

func ThresholdInstanceTest(threshold, numPlayers int, t *testing.T) {
	type pkSlice []*bls.PublicKey
	type skSlice []*bls.SecretKey

	// commitments := make([]pkSlice, threshold)
	var commitments []pkSlice
	fragments := make([]skSlice, numPlayers)
	secrets := make(skSlice, numPlayers)

	// TODO: Remove these temp aliases later
	T := threshold
	N := numPlayers

	// Step 1 : ThresholdCreate
	for player := 0; player < numPlayers; player++ {
		sk, commis, fragis, err := bls.ThresholdCreate(threshold, numPlayers)
		if err != nil {
			panic(err)
		}
		for j, frag := range fragis {
			fragments[j] = append(fragments[j], frag)
		}
		commitments = append(commitments, commis)
		secrets[player] = sk
	}

	// Step 2 : ThresholdVerifySecretFragment
	for playerSource := 1; playerSource <= numPlayers; playerSource++ {
		for playerTarget := 1; playerTarget <= numPlayers; playerTarget++ {
			didItWork := bls.ThresholdVerifySecretFragment(
				T,
				playerTarget,
				fragments[playerTarget-1][playerSource-1],
				commitments[playerSource-1],
			)
			if !didItWork {
				t.Error("did not work")
			}
		}
	}

	// Step 3 : masterPubkey = AggregatePublicKeys(...)
	//          secretShare = AggregateSecretKeys(...)
	pksToAggregate := make(pkSlice, len(commitments))
	for i, cpoly := range commitments {
		pksToAggregate[i] = cpoly[0]
	}
	masterPubKey := bls.AggregatePublicKeys(pksToAggregate, false)
	fmt.Printf("masterPubKey: %x\n", masterPubKey.Serialize())

	secretShares := make([]*bls.SecretKey, len(fragments))
	for i, row := range fragments {
		ss := bls.AggregateSecretKeys([]*bls.SecretKey(row), nil, false)
		secretShares[i] = ss
	}

	masterSecretKey := bls.AggregateSecretKeys([]*bls.SecretKey(secrets), nil, false)
	msg := []byte("Test")
	signatureActual := masterSecretKey.Sign(msg)
	fmt.Printf("signatureActual: %x\n", signatureActual.Serialize())

	//if !signatureActual.Verify() {
	//	t.Error("sig did not verify")
	//}

	// Step 4 : sigShare = secretShare.SignThreshold(...)
	// Check every combination of T players
	Combinations(N, T, func(X []int) {
		// Add one to each value of X
		X1 := plusOne(X)

		lenX := len(X)
		listShares := make([]*bls.FR, lenX)
		signatureShares := make([]*bls.Signature, lenX)

		for i, x := range X {
			listShares[i] = secretShares[x].GetValue()
			signatureShares[i] = secretShares[x].SignWithCoefficent(msg, x+1, X1)
		}

		// Check underlying secret key is correct
		r := bls.ThresholdInterpolateAtZero(X1, listShares)
		secretCand := bls.NewSecretKey(r)
		if bytes.Compare(secretCand.Serialize(), masterSecretKey.Serialize()) != 0 {
			t.Error("candidate secret key does not match master secret key")
		}

		// Check signatures
		signatureCand := bls.AggregateSignaturesSimple(signatureShares)
		if bytes.Compare(signatureCand.Serialize(), signatureActual.Serialize()) != 0 {
			t.Error("candidate signature does not match actual signature")
		}
	})

}

func plusOne(iSlice []int) []int {
	plusOne := make([]int, len(iSlice))
	for i, v := range iSlice {
		plusOne[i] = v + 1
	}
	return plusOne
}

func TestThreshold(t *testing.T) {
	ThresholdInstanceTest(1, 1, t)
	ThresholdInstanceTest(1, 2, t)
	ThresholdInstanceTest(2, 2, t)
	for i := 1; i < 6; i++ {
		ThresholdInstanceTest(i, 5, t)
	}
}

// from Filippo Valsorda:
// https://filippo.io/callback-based-combinations-in-go/
func Combinations(n, m int, f func([]int)) {
	// For each combination of m elements out of n
	// call the function f passing a list of m integers in 0-n
	// without repetitions

	// TODO: switch to iterative algo
	s := make([]int, m)
	last := m - 1
	var rc func(int, int)
	rc = func(i, next int) {
		for j := next; j < n; j++ {
			s[i] = j
			if i == last {
				f(s)
			} else {
				rc(i+1, j+1)
			}
		}
		return
	}
	rc(0, 0)
}
