package bls

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// TODO: Godoc. Threshold Namespace?
// Utility functions for threshold signatures

// VerifySecretFragment ...
//func VerifySecretFragment(T, player int, secretFragment *FQ, commitments []*PublicKey) {
//}

// Create returns a new private key with associated data suitable for T of N
// threshold signatures under a Joint-Feldman scheme.
//
// After the dealing phase, one needs cooperation of T players out of N in
// order to sign a message with the master key pair.
//
// Return:
// - poly[0] - your share of the master secret key
// - commitments to your polynomial P
// - secret_fragments[j] = P(j), to be sent to player j
//
// (All N secret_fragments[j] can be combined to make a secret share.)
func Create(thresholdParameter, numPlayers int) (*SecretKey, []*PublicKey, []*SecretKey, error) {
	if thresholdParameter < 1 || thresholdParameter > numPlayers {
		return nil, nil, nil, fmt.Errorf("threshold parameter must be between 1 and number of players")
	}

	g1 := NewG1Affine(NewFQ(g1GeneratorX), NewFQ(g1GeneratorY))
	poly := make([]*FR, thresholdParameter)
	commitments := make([]*PublicKey, thresholdParameter)
	secretFragments := make([]*SecretKey, thresholdParameter)

	// Range over T, e.g. thresholdParameter
	for i := 0; i < thresholdParameter; i++ {
		frPtr, err := RandFR(rand.Reader)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("could not get RandFR: %v", err.Error())
		}
		poly[i] = frPtr
		commitments[i] = NewPublicKey(g1.Mul(frPtr.ToBig()))
	}

	// Range over N, e.g. numPlayers
	for x := 0; x < numPlayers; x++ {
		// Create a new FR secret fragment
		sf := NewFR(bigZero)
		for i, c := range poly {
			// Add to the fragment
			sf.Add(
				// Multiply c by x^i % n
				c.Mul(
					// NewFR not needed as Exp mods by the RFieldModulus already
					&FR{n: new(big.Int).Exp(big.NewInt(int64(x+1)), big.NewInt(int64(i)), RFieldModulus)},
				),
			)
		}
		// The fragment is done w/summation, add to the fragments list
		secretFragments[x] = NewSecretKey(sf)
	}

	return &SecretKey{f: poly[0]}, commitments, secretFragments, nil
}
