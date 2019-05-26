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

// ThresholdInterpolateAtZero ...
//
// The points (X[i], Y[i]) for i = 0...T-1 interpolate into P,
// a degree T-1 polynomial.  Returns P(0).
func ThresholdInterpolateAtZero(x []int, y []*FR) *FR {
	ans := FRZero.Copy()

	//if T <= 0 {
	//	// "T must be a positive integer"
	//	panic("T must be a positive integer")
	//}

	coeffs := LagrangeCoeffsAtZero()

	// LagrangeCoeffsAtZero(x []int) []*FR

	return FRZero
}

// LagrangeCoeffsAtZero returns lagrange coefficients of a polynomial
// evaluated at zero.
//
// If we have T points (players[i], P(players[i])), it interpolates to a degree
// T-1 polynomial P.  The returned coefficients are such that P(0) = sum_i
// res[i] * P(players[i]).
//
// TODO/NGM: Assume this should be a slice of *FRs and then the mod check below not needed.
func LagrangeCoeffsAtZero(x []int) []*FR {
	lenX := len(x)

	// Ensure each value in X is unique.
	mapSeenX := make(map[int]struct{}, lenX)
	for i := 0; i < lenX; i++ {
		val := x[i]
		_, found := mapSeenX[val]
		if found {
			// TODO: Don't panic
			panic("must not have duplicate player indices")
		}
		mapSeenX[val] = struct{}{}

		// Also ensure value is less than RFieldModulus
		if big.NewInt(int64(val)).Cmp(RFieldModulus) != -1 {
			// TODO: Don't panic
			panic("player index must be less then n (RFieldModulus)")
		}

		// ... and > 0
		if val <= 0 {
			// TODO: Don't panic
			panic("player index must be positive")
		}
	}

	weight := func(j int) *FR {
		ans := FROne.Copy()
		for i := 0; i < lenX; i++ {
			if i != j {
				bigJ := big.NewInt(int64(x[j]))
				bigI := big.NewInt(int64(x[i]))
				ans.MulAssign(NewFR(new(big.Int).Sub(bigJ, bigI)))
			}
		}
		return ans.Inverse()
	}

	// Using the second barycentric form,
	// P(0) = (sum_j (y_j * w_j / x_j)) / (sum_j w_j/x_j)
	// If desired, the weights can be precomputed.
	ans := make([]*FR, lenX)
	denom := FRZero.Copy()

	for j := 0; j < lenX; j++ {
		bigJ := big.NewInt(int64(x[j]))
		jFR := NewFR(bigJ)
		shift := weight(j).Mul(jFR.Neg().Inverse())
		ans[j] = shift
		denom.AddAssign(shift)
	}
	denom = denom.Inverse()

	for i := 0; i < lenX; i++ {
		ans[i].MulAssign(denom)
	}

	return ans
}
