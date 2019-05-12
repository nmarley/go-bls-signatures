package bls

import (
	"fmt"
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
// Performs a double and add algorithm for the ate pairing. This algorithm
// is taken from Craig Costello's "Pairing for Beginners".
func XMillerLoop(t *big.Int, p *G1Projective, q *G2Projective) *FQ12 {
	tBits := IntToBits(t)
	fmt.Println("NGMgo(XMillerLoop) tBits:", tBits)

	// TODO: Remove dummy return
	return FQ12Zero
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

//def miller_loop(T, P, Q, ec=default_ec):
//    T_bits = int_to_bits(T)
//    R = Q
//    f = Fq12.one(ec.q)  # f is an element of Fq12
//    for i in range(1, len(T_bits)):
//        # Compute sloped line lrr
//        lrr = double_line_eval(R, P, ec)
//        f = f * f * lrr
//
//        R = 2 * R
//        if T_bits[i] == 1:
//            # Compute sloped line lrq
//            lrq = add_line_eval(R, Q, P, ec)
//            f = f * lrq
//
//            R = R + Q
//    return f
