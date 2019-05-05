package bls

import (
	"math/big"
)

var bigFour = big.NewInt(4)
var FQFour = NewFQ(bigFour)

// a,b and a2, b2, define the elliptic curve and twisted curve.
// y^2 = x^3 + 4
// y^2 = x^3 + 4(u + 1)
var a = FQZero
var b = FQFour

var aTwist = FQ2Zero
var bTwist = NewFQ2(FQFour, FQFour)
