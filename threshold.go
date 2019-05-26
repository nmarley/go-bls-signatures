package bls

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// TODO: Godoc. Threshold Namespace?
// Utility functions for threshold signatures

// ThresholdVerifySecretFragment returns true iff the secretFragment from the
// given player matches their given commitment to a polynomial.
func ThresholdVerifySecretFragment(thresholdParameter, numPlayer int, secretFragment *SecretKey, commitments []*PublicKey) bool {
	// TODO: s/numPlayer/player(Index)?/

	// TODO: Can hard-code this as g1 generator point
	if thresholdParameter <= 0 {
		// "T must be a positive integer"
		panic("T must be a positive integer")
		return false
	} else if numPlayer <= 0 {
		// "Player index must be positive"
		panic("Player index must be positive")
		return false
	}

	g1 := NewG1Affine(NewFQ(g1GeneratorX), NewFQ(g1GeneratorY))

	lhs := g1.Mul(secretFragment.f.ToBig())
	rhs := commitments[0].p.Copy()

	for i := 1; i < len(commitments); i++ {
		factor := new(big.Int).Exp(
			big.NewInt(int64(numPlayer)),
			big.NewInt(int64(i)),
			RFieldModulus,
		)
		rhs = rhs.Add(commitments[i].p.Mul(factor))
	}

	return lhs.ToAffine().Equal(rhs.ToAffine())
}

// ThresholdCreate returns a new private key with associated data suitable for T of N
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
func ThresholdCreate(thresholdParameter, numPlayers int) (*SecretKey, []*PublicKey, []*SecretKey, error) {
	if thresholdParameter < 1 || thresholdParameter > numPlayers {
		return nil, nil, nil, fmt.Errorf("threshold parameter must be between 1 and number of players")
	}

	// TODO: Can hard-code this as g1 generator point
	g1 := NewG1Affine(NewFQ(g1GeneratorX), NewFQ(g1GeneratorY))

	// There are T polynomials / commitments
	poly := make([]*FR, thresholdParameter)
	commitments := make([]*PublicKey, thresholdParameter)

	// There are N secret fragments
	secretFragments := make([]*SecretKey, numPlayers)

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
			sf.AddAssign(
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

	return NewSecretKey(poly[0]), commitments, secretFragments, nil
}
