package bls

import (
	"math/big"
)

// MillerLoopItem are the inputs to the miller loop.
type MillerLoopItem struct {
	P *G1Affine
	Q *G2Prepared
}

type pairingItem struct {
	p      *G1Affine
	q      [][3]*FQ2
	qIndex int
}

// MillerLoop runs the miller loop algorithm.
func MillerLoop(items []MillerLoopItem) *FQ12 {
	pairs := make([]pairingItem, len(items))
	for i, item := range items {
		if !item.P.IsZero() && !item.Q.IsZero() {
			pairs[i] = pairingItem{
				p:      item.P.Copy(),
				q:      item.Q.coeffs,
				qIndex: 0,
			}
		}
	}

	ell := func(f *FQ12, coeffs [3]*FQ2, p *G1Affine) *FQ12 {
		c0 := coeffs[0]
		c1 := coeffs[1]

		c0.c0.MulAssign(p.y)
		c0.c1.MulAssign(p.y)
		c1.c0.MulAssign(p.x)
		c1.c1.MulAssign(p.x)

		return f.MulBy014(coeffs[2], c1, c0)
	}

	f := FQ12One.Copy()

	foundOne := false
	blsXRsh1 := new(big.Int).Rsh(blsX, 1)
	bs := blsXRsh1.Bytes()
	for i := uint(0); i < uint(len(bs)*8); i++ {
		segment := i / 8
		bit := 7 - i%8
		set := bs[segment]&(1<<bit) > 0
		if !foundOne {
			foundOne = set
			continue
		}

		for i, pair := range pairs {
			f = ell(f, pair.q[pair.qIndex], pair.p.Copy())
			pairs[i].qIndex++
		}
		if set {
			for i, pair := range pairs {
				f = ell(f, pair.q[pair.qIndex], pair.p.Copy())
				pairs[i].qIndex++
			}
		}

		f = f.Square()
	}
	for i, pair := range pairs {
		f = ell(f, pair.q[pair.qIndex], pair.p.Copy())
		pairs[i].qIndex++
	}

	if blsIsNegative {
		f = f.Conjugate()
	}
	return f
}

// FinalExponentiation performs the final exponentiation on the
// FQ12 element.
func FinalExponentiation(r *FQ12) *FQ12 {
	f1 := r.Conjugate()
	f2 := r.Inverse()
	if f1 == nil {
		return nil
	}
	r = f1.Mul(f2)
	f2 = r.Copy()
	r.FrobeniusMapAssign(2)
	r.MulAssign(f2)

	ExpByX := func(f *FQ12, x *big.Int) *FQ12 {
		newf := f.Exp(x)
		if blsIsNegative {
			newf.ConjugateAssign()
		}
		return newf
	}

	x := new(big.Int).Set(blsX)

	y0 := r.Square()
	y1 := ExpByX(y0, x)
	x.Rsh(x, 1)
	y2 := ExpByX(y1, x)
	x.Lsh(x, 1)
	y3 := r.Conjugate()
	y1 = y1.Mul(y3)
	y1.ConjugateAssign()
	y1.MulAssign(y2)
	y2 = ExpByX(y1, x)
	y3 = ExpByX(y2, x)
	y1.ConjugateAssign()
	y3.MulAssign(y1)
	y1.ConjugateAssign()
	y1.FrobeniusMapAssign(3)
	y2.FrobeniusMapAssign(2)
	y1.MulAssign(y2)
	y2 = ExpByX(y3, x)
	y2.MulAssign(y0)
	y2.MulAssign(r)
	y1.MulAssign(y2)
	y3.FrobeniusMapAssign(1)
	y1.MulAssign(y3)
	return y1
}

// Pairing performs a pairing given the G1 and G2 elements.
func Pairing(p *G1Projective, q *G2Projective) *FQ12 {
	return FinalExponentiation(
		MillerLoop(
			[]MillerLoopItem{
				{p.ToAffine(), G2AffineToPrepared(q.ToAffine())},
			},
		),
	)
}

// XMillerLoop ...
//
// Performs a double and add algorithm for the ate pairing. This algorithm is
// taken from Craig Costello's "Pairing for Beginners".
func XMillerLoop(t *big.Int, p *G1Projective, q *G2Projective) *FQ12 {
	tBits := IntToBits(t)

	r := q.Copy()
	f := FQ12One.Copy()

	for i := 1; i < len(tBits); i++ {
		// Compute sloped line lrr
		lrr := DoubleLineEval(r, p)

		f = f.Mul(f).Mul(lrr)

		// R = 2 * R
		r = r.Double()

		if tBits[i] == 1 {
			// Compute sloped line lrq
			lrq := AddLineEval(r, q, p)

			// f = f * lrq
			f = f.Mul(lrq)

			// R = R + Q
			r = r.Add(q)
		}
	}

	return f
}

// XFinalExponentiation ...
//
// Performs a final exponentiation to map the result of the miller loop to a
// unique element of Fq12.
func XFinalExponentiation(r *FQ12) *FQ12 {
	// ans = pow(element, (pow(ec.q,4) - pow(ec.q,2) + 1) // ec.n)
	inner1 := new(big.Int).Exp(QFieldModulus, bigFour, nil)
	inner2 := new(big.Int).Exp(QFieldModulus, bigTwo, nil)
	innerExp := new(big.Int).Sub(inner1, inner2)
	innerExp.Add(innerExp, bigOne)
	innerExp.Div(innerExp, RFieldModulus)
	ans := r.Exp(innerExp)

	// ans = ans.qi_power(2) * ans
	ans = ans.FrobeniusMap(2).Mul(ans)

	//ans = ans.qi_power(6) / ans
	ans = ans.FrobeniusMap(6).Mul(ans.Inverse())

	return ans
}

// DoubleLineEval ...
//
// Creates an equation for a line tangent to R, and evaluates this at the point
// P. f(x) = y - sv - v.  f(P).
func DoubleLineEval(r *G2Projective, p *G1Projective) *FQ12 {
	// R12 = untwist(R)
	r12 := r.ToAffine().Untwist()

	// slope = (3 * pow(R12.x, 2) + ec.a) / (2 * R12.y)
	r12_sq := r12.x.Mul(r12.x)
	r12_sq_3x := r12_sq.Add(r12_sq).Add(r12_sq)
	r12_y_2 := r12.y.Add(r12.y)
	slope := r12_sq_3x.Mul(r12_y_2.Inverse())

	// v = R12.y - slope * R12.x
	v := r12.y.Sub(slope.Mul(r12.x))
	xSlope := slope.MulFQ(p.ToAffine().x)

	// return P.y - P.x * slope - v
	return xSlope.Neg().AddFQ(p.ToAffine().y).Sub(v)
}

// AddLineEval...
//
// Creates an equation for a line between R and Q, and evaluates this at the
// point P. f(x) = y - sv - v.  f(P).
func AddLineEval(r, q *G2Projective, p *G1Projective) *FQ12 {
	// R12 = untwist(R)
	// Q12 = untwist(Q)
	r12 := r.ToAffine().Untwist()
	q12 := q.ToAffine().Untwist()

	// This is the case of a vertical line, where the denominator
	// will be 0.
	// if R12 == Q12.negate():
	//     return P.x - R12.x
	if r12.Equal(q12.Conjugate()) {
		return r12.x.Neg().AddFQ(p.ToAffine().x)
	}

	// slope = (Q12.y - R12.y) / (Q12.x - R12.x)
	slope := q12.y.Sub(r12.y).Mul(q12.x.Sub(r12.x).Inverse())

	// v = (Q12.y * R12.x - R12.y * Q12.x) / (R12.x - Q12.x)
	v := q12.y.Mul(r12.x).Sub(r12.y.Mul(q12.x)).Mul(r12.x.Sub(q12.x).Inverse())

	// return P.y - P.x * slope - v
	return slope.MulFQ(p.ToAffine().x).Neg().AddFQ(p.ToAffine().y).Sub(v)
}

// []big.Word
// TODO: optimize this
func IntToBits(n *big.Int) []byte {
	n.Bits()

	if n.Cmp(bigOne) == -1 {
		return []byte{0}
	}

	var bits []byte
	for n.Cmp(bigZero) == 1 {
		// this will be one or zero
		bit := new(big.Int).Mod(n, bigTwo).Bit(0)
		bits = append(bits, byte(bit))

		// Halve n by right shifting bits
		n = new(big.Int).Rsh(n, 1)
	}

	// reverse bits
	newBits := make([]byte, len(bits))
	for i, j := len(bits), 0; i > 0; i, j = i-1, j+1 {
		newBits[j] = bits[i-1]
	}

	return newBits
}

// AtePairingMulti ...
//
// Computes multiple pairings at once. This is more efficient, since we can
// multiply all the results of the miller loops, and perform just one final
// exponentiation.
func AtePairingMulti(ps []*G1Projective, qs []*G2Projective) *FQ12 {
	negX := new(big.Int).Neg(blsX)
	t := new(big.Int).Add(negX, bigOne)
	bigT := new(big.Int).Abs(new(big.Int).Sub(t, bigOne))

	prod := FQ12One.Copy()

	for i, q := range qs {
		p := ps[i]
		prod = prod.Mul(XMillerLoop(bigT, p, q))
	}

	return XFinalExponentiation(prod)
}

// AtePairing ...
func AtePairing(p *G1Projective, q *G2Projective) *FQ12 {
	return FQ12Zero
}
