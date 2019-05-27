package bls_test

import (
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
	//N := players

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
	//masterPubkey := bls.AggregatePublicKeys(pksToAggregate, false)
	//
	//for i, row := range fragments {
	//	//AggregateS
	//	//ss :=
	//}
	//secretShares :=

}

func TestThreshold(t *testing.T) {
	ThresholdInstanceTest(1, 1, t)
	//ThresholdInstanceTest(1, 2, t)
	//ThresholdInstanceTest(2, 2, t)
	//for i := 1; i < 6; i++ {
	//	ThresholdInstanceTest(i, 5, t)
	//}
}
