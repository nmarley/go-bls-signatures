package bls

import (
	"fmt"
	"io"
	"math/big"
)

// FQ12 is an element of Fq12, represented by c0 + c1 * w.
type FQ12 struct {
	c0 *FQ6
	c1 *FQ6
}

// NewFQ12 creates a new FQ12 element from two FQ6 elements.
func NewFQ12(c0 *FQ6, c1 *FQ6) *FQ12 {
	return &FQ12{
		c0: c0,
		c1: c1,
	}
}

// String implements the stringer interface
func (f FQ12) String() string {
	return fmt.Sprintf("Fq12(%s + %s * w)", f.c0, f.c1)
}

// Serialize the element as a hex string
func (f FQ12) Serialize() string {
	return fmt.Sprintf("Fq12(%s + %s * w)", f.c0.Serialize(), f.c1.Serialize())
}

// Conjugate returns the conjugate of the FQ12 element.
func (f *FQ12) Conjugate() *FQ12 {
	return NewFQ12(f.c0, f.c1.Neg())
}

// ConjugateAssign returns the conjugate of the FQ12 element.
func (f *FQ12) ConjugateAssign() {
	f.c1.NegAssign()
}

// MulBy014 multiplies FQ12 element by 3 FQ2 elements.
func (f *FQ12) MulBy014(c0 *FQ2, c1 *FQ2, c4 *FQ2) *FQ12 {
	aa := f.c0.MulBy01(c0, c1)
	bb := f.c1.MulBy1(c4)
	o := c1.Add(c4)
	c1Out := f.c1.Copy()
	c1Out.AddAssign(f.c0)
	c1Out.MulBy01Assign(c0, o)
	c1Out.SubAssign(aa)
	c1Out.SubAssign(bb)
	outB := bb.MulByNonresidue()
	outB.AddAssign(aa)
	return NewFQ12(
		outB,
		c1Out,
	)
}

// FQ12Zero is the zero element of FQ12.
var FQ12Zero = NewFQ12(FQ6Zero, FQ6Zero)

// FQ12One is the one element of FQ12.
var FQ12One = NewFQ12(FQ6One, FQ6Zero)

// Equals checks if two FQ12 elements are equal.
func (f FQ12) Equals(other *FQ12) bool {
	return f.c0.Equals(other.c0) && f.c1.Equals(other.c1)
}

// Double doubles each coefficient in an FQ12 element.
func (f FQ12) Double() *FQ12 {
	return NewFQ12(f.c0.Double(), f.c1.Double())
}

// Neg negates each coefficient in an FQ12 element.
func (f FQ12) Neg() *FQ12 {
	return NewFQ12(f.c0.Neg(), f.c1.Neg())
}

// Add adds two FQ12 elements together.
func (f FQ12) Add(other *FQ12) *FQ12 {
	return NewFQ12(
		f.c0.Add(other.c0),
		f.c1.Add(other.c1),
	)
}

// Sub subtracts one FQ12 element from another.
func (f FQ12) Sub(other *FQ12) *FQ12 {
	return NewFQ12(
		f.c0.Sub(other.c0),
		f.c1.Sub(other.c1),
	)
}

// RandFQ12 generates a random FQ12 element.
func RandFQ12(reader io.Reader) (*FQ12, error) {
	a, err := RandFQ6(reader)
	if err != nil {
		return nil, err
	}
	b, err := RandFQ6(reader)
	if err != nil {
		return nil, err
	}
	return NewFQ12(a, b), nil
}

// Copy returns a copy of the FQ12 element.
func (f FQ12) Copy() *FQ12 {
	return NewFQ12(f.c0.Copy(), f.c1.Copy())
}

// Exp raises the element ot a specific power.
func (f FQ12) Exp(n *big.Int) *FQ12 {
	nCopy := new(big.Int).Set(n)
	res := FQ12One.Copy()
	fi := f.Copy()
	for nCopy.Cmp(bigZero) != 0 {
		if !isEven(nCopy) {
			res.MulAssign(fi)
		}
		fi.MulAssign(fi)
		nCopy.Rsh(nCopy, 1)
	}
	return res
}

var bigSix = big.NewInt(6)

func getFrobExpMinus1Over6(power int64) *big.Int {
	return new(big.Int).Div(new(big.Int).Sub(new(big.Int).Exp(QFieldModulus, big.NewInt(power), nil), bigOne), bigSix)
}

var frobeniusCoeffFQ12c1 = [12]*FQ2{
	FQ2One,
	fq2nqr.Exp(getFrobExpMinus1Over6(1)),
	fq2nqr.Exp(getFrobExpMinus1Over6(2)),
	fq2nqr.Exp(getFrobExpMinus1Over6(3)),
	fq2nqr.Exp(getFrobExpMinus1Over6(4)),
	fq2nqr.Exp(getFrobExpMinus1Over6(5)),
	fq2nqr.Exp(getFrobExpMinus1Over6(6)),
	fq2nqr.Exp(getFrobExpMinus1Over6(7)),
	fq2nqr.Exp(getFrobExpMinus1Over6(8)),
	fq2nqr.Exp(getFrobExpMinus1Over6(9)),
	fq2nqr.Exp(getFrobExpMinus1Over6(10)),
	fq2nqr.Exp(getFrobExpMinus1Over6(11)),
}

// FrobeniusMap calculates the frobenius map of an FQ12 element.
func (f FQ12) FrobeniusMap(power uint8) *FQ12 {
	c1 := f.c1.FrobeniusMap(power)
	return NewFQ12(
		f.c0.FrobeniusMap(power),
		NewFQ6(
			c1.c0.Mul(frobeniusCoeffFQ12c1[power%12]),
			c1.c1.Mul(frobeniusCoeffFQ12c1[power%12]),
			c1.c2.Mul(frobeniusCoeffFQ12c1[power%12]),
		),
	)
}

// FrobeniusMapAssign calculates the frobenius map of an FQ12 element.
func (f *FQ12) FrobeniusMapAssign(power uint8) {
	f.c0.FrobeniusMapAssign(power)
	f.c1.FrobeniusMapAssign(power)
	f.c1.c0.MulAssign(frobeniusCoeffFQ12c1[power%12])
	f.c1.c1.MulAssign(frobeniusCoeffFQ12c1[power%12])
	f.c1.c2.MulAssign(frobeniusCoeffFQ12c1[power%12])
}

// Square calculates the square of the FQ12 element.
func (f FQ12) Square() *FQ12 {
	ab := f.c0.Mul(f.c1)
	c0c1 := f.c0.Add(f.c1)
	c0 := f.c1.MulByNonresidue().Add(f.c0).Mul(c0c1).Sub(ab)
	c1 := ab.Add(ab)
	ab = ab.MulByNonresidue()
	return NewFQ12(
		c0.Sub(ab),
		c1,
	)
}

// SquareAssign squares the FQ2 element.
func (f *FQ12) SquareAssign() {
	ab := f.c0.Mul(f.c1)
	c0 := f.c1.Neg()
	c0.AddAssign(f.c0)
	f.c0.AddAssign(f.c1)
	c0.MulAssign(f.c0)
	c0.SubAssign(ab)
	c0.AddAssign(ab)
	ab.AddAssign(ab)
	f.c0 = c0
	f.c1 = ab
}

// Mul multiplies two FQ12 elements together.
func (f FQ12) Mul(other *FQ12) *FQ12 {
	aa := f.c0.Copy()
	aa.MulAssign(other.c0)
	bb := f.c1.Copy()
	bb.MulAssign(other.c1)
	o := other.c0.Add(other.c1)
	out := f.c1.Add(f.c0)
	out.MulAssign(o)
	out.SubAssign(aa)
	out.SubAssign(bb)
	bb = bb.MulByNonresidue()
	bb.AddAssign(aa)
	return NewFQ12(
		bb,
		out,
	)
}

// MulAssign multiplies two FQ12 elements together.
func (f *FQ12) MulAssign(other *FQ12) {
	aa := f.c0.Copy()
	aa.MulAssign(other.c0)
	bb := f.c1.Copy()
	bb.MulAssign(other.c1)
	o := other.c0.Copy()
	o.AddAssign(other.c1)

	f.c1 = f.c1.Add(f.c0)
	f.c1.MulAssign(o)
	f.c1.SubAssign(aa)
	f.c1.SubAssign(bb)
	f.c0 = bb.MulByNonresidue()
	f.c0.AddAssign(aa)
}

// Inverse finds the inverse of an FQ12
func (f FQ12) Inverse() *FQ12 {
	c1s := f.c1.Square().MulByNonresidue()
	c0s := f.c0.Square().Sub(c1s)

	i := c0s.Inverse()
	if i == nil {
		return nil
	}

	return NewFQ12(i.Mul(f.c0), i.Mul(f.c1).Neg())
}

// MulFQ multiplies the FQ12 by a FQ element
func (f *FQ12) MulFQ(fq *FQ) *FQ12 {
	c0 := FQ6Zero.Copy()
	c1 := FQ6Zero.Copy()

	if !f.c0.IsZero() {
		c0 = f.c0.MulFQ(fq)
	}
	if !f.c1.IsZero() {
		c1 = f.c1.MulFQ(fq)
	}

	return NewFQ12(c0, c1)
}

func (f FQ12) PP() string {
	return fmt.Sprintf("\nFq12(\n%s,\n%s\n)", f.c0.PP(4), f.c1.PP(4))
}
