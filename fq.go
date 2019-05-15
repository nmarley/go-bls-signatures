package bls

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"hash"
	"io"
	"math/big"
)

// FQ is an element in a field.
type FQ struct {
	n *big.Int
}

var bigZero = big.NewInt(0)
var bigOne = big.NewInt(1)
var bigTwo = big.NewInt(2)

// QFieldModulus is the modulus of the field.
// 381 bit prime defining the field Fq. q = (x - 1)2 ((x4 - x2 + 1) / 3) + x
var QFieldModulus, _ = new(big.Int).SetString("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16)

// NewFQ creates a new field element.
func NewFQ(n *big.Int) *FQ {
	outN := n
	if n.Cmp(QFieldModulus) >= 0 || n.Cmp(bigZero) < 0 {
		outN.Mod(outN, QFieldModulus)
	}
	return &FQ{n: outN}
}

// Copy creates a copy of the field element.
func (f FQ) Copy() *FQ {
	return &FQ{n: new(big.Int).Set(f.n)}
}

// Add adds two field elements together.
func (f FQ) Add(other *FQ) *FQ {
	out := new(big.Int).Add(f.n, other.n)
	if out.Cmp(QFieldModulus) >= 0 || out.Cmp(bigZero) < 0 {
		out.Mod(out, QFieldModulus)
	}
	return &FQ{n: out}
}

// AddAssign multiplies a field element by this one.
func (f FQ) AddAssign(other *FQ) {
	f.n.Add(f.n, other.n)
	if f.n.Cmp(QFieldModulus) >= 0 || f.n.Cmp(bigZero) < 0 {
		f.n.Mod(f.n, QFieldModulus)
	}
}

// Mul multiplies two field elements together.
func (f FQ) Mul(other *FQ) *FQ {
	out := new(big.Int).Mul(f.n, other.n)
	out.Mod(out, QFieldModulus)
	return &FQ{n: out}
}

// MulAssign multiplies a field element by this one.
func (f FQ) MulAssign(other *FQ) {
	f.n.Mul(f.n, other.n)
	if f.n.Cmp(QFieldModulus) < 0 && f.n.Cmp(bigZero) > 0 {
		return
	} else if f.n.BitLen() < 386 && f.n.Sign() == 1 {
		for f.n.Cmp(QFieldModulus) >= 0 {
			f.n.Sub(f.n, QFieldModulus)
		}
	} else {
		f.n.Mod(f.n, QFieldModulus)
	}
}

// Sub subtracts one field element from the other.
func (f FQ) Sub(other *FQ) *FQ {
	out := new(big.Int).Sub(f.n, other.n)
	if out.Cmp(QFieldModulus) >= 0 || out.Cmp(bigZero) < 0 {
		out.Mod(out, QFieldModulus)
	}
	return &FQ{n: out}
}

// SubAssign subtracts a field element from this one.
func (f FQ) SubAssign(other *FQ) {
	f.n.Sub(f.n, other.n)
	if f.n.Cmp(QFieldModulus) >= 0 || f.n.Cmp(bigZero) < 0 {
		f.n.Mod(f.n, QFieldModulus)
	}
}

// Exp exponentiates the field element to the given power.
func (f FQ) Exp(n *big.Int) *FQ {
	return &FQ{
		n: new(big.Int).Exp(f.n, n, QFieldModulus),
	}
}

// ExpAssign exponentiates the field element to the given power.
func (f *FQ) ExpAssign(n *big.Int) {
	f.n.Exp(f.n, n, QFieldModulus)
}

// Equals checks equality of two field elements.
func (f FQ) Equals(other *FQ) bool {
	return f.n.Cmp(other.n) == 0
}

// Neg gets the negative value of the field element mod QFieldModulus.
func (f FQ) Neg() *FQ {
	return NewFQ(new(big.Int).Neg(f.n))
}

// NegAssign gets the negative value of the field element mod QFieldModulus.
func (f *FQ) NegAssign() {
	f.n.Neg(f.n)
	f.n.Mod(f.n, QFieldModulus)
}

// String implements the Stringer interface
func (f FQ) String() string {
	hexStr := fmt.Sprintf("%x", f.n)

	// If the hex representation of f.n is greater than 8 hex digits, shorten
	// it
	if 1 == f.n.Cmp(big.NewInt(0xffffffff)) {
		hexStr = hexStr[0:5] + ".." + hexStr[(len(hexStr)-5):]
	}

	return fmt.Sprintf("Fq(0x%s)", hexStr)
}

// Serialize prints the full serialized value as a hex string.
// TODO: Rename this to Hex() or something... serialize has the expectation of bytes
func (f FQ) Serialize() string {
	return fmt.Sprintf("%096x", f.n)
}

// Cmp compares this field element to another.
func (f FQ) Cmp(other *FQ) int {
	return f.n.Cmp(other.n)
}

// Double doubles the element
func (f FQ) Double() *FQ {
	return NewFQ(new(big.Int).Lsh(f.n, 1))
}

// DoubleAssign doubles the element
func (f *FQ) DoubleAssign() {
	f.n.Lsh(f.n, 1)
	f.n.Mod(f.n, QFieldModulus)
}

// IsZero checks if the field element is zero.
func (f FQ) IsZero() bool {
	return f.n.Cmp(bigZero) == 0
}

// Square squares a field element.
func (f FQ) Square() *FQ {
	return NewFQ(new(big.Int).Mul(f.n, f.n))
}

// SquareAssign squares a field element.
func (f *FQ) SquareAssign() {
	f.n.Mul(f.n, f.n)
	f.n.Mod(f.n, QFieldModulus)
}

var negativeOneFQ = NewFQ(negativeOne)

// Sqrt calculates the square root of the field element.
func (f FQ) Sqrt() *FQ {
	// Shank's algorithm for q mod 4 = 3
	// https://eprint.iacr.org/2012/685.pdf (page 9, algorithm 2)

	a1 := f.Exp(qMinus3Over4)
	a0 := a1.Square()
	a0.MulAssign(&f)

	if a0.Equals(negativeOneFQ) {
		return nil
	}
	a1.MulAssign(&f)
	return a1
}
func isEven(b *big.Int) bool {
	return b.Bit(0) == 0
}

// Inverse finds the inverse of the field element.
func (f FQ) Inverse() *FQ {
	if f.IsZero() {
		return nil
	}
	u := new(big.Int).Set(f.n)
	v := new(big.Int).Set(QFieldModulus)
	b := NewFQ(new(big.Int).Set(bigOne))
	c := FQZero.Copy()

	for u.Cmp(bigOne) != 0 && v.Cmp(bigOne) != 0 {
		for isEven(u) {
			u.Div(u, bigTwo)
			if isEven(b.n) {
				b.n.Div(b.n, bigTwo)
			} else {
				b.n.Add(b.n, QFieldModulus)
				b.n.Div(b.n, bigTwo)
			}
		}

		for isEven(v) {
			v.Div(v, bigTwo)
			if isEven(c.n) {
				c.n.Div(c.n, bigTwo)
			} else {
				c.n.Add(c.n, QFieldModulus)
				c.n.Div(c.n, bigTwo)
			}
		}

		if u.Cmp(v) >= 0 {
			u.Sub(u, v)
			b.SubAssign(c)
		} else {
			v.Sub(v, u)
			c.SubAssign(b)
		}
	}
	if u.Cmp(bigOne) == 0 {
		return b
	}
	return c
}

// Parity checks if the point is greater than the point negated.
func (f FQ) Parity() bool {
	neg := f.Neg()
	return f.Cmp(neg) > 0
}

// MulBits multiplies the number by a big number.
func (f FQ) MulBits(b *big.Int) *FQ {
	res := FQZero.Copy()
	for i := 0; i < b.BitLen(); i++ {
		res.DoubleAssign()
		if b.Bit(b.BitLen()-1-i) == 1 {
			res.AddAssign(&f)
		}
	}
	return res
}

// HashFQ calculates a new FQ2 value based on a hash.
func HashFQ(hasher hash.Hash) *FQ {
	digest := hasher.Sum(nil)
	newB := new(big.Int).SetBytes(digest)
	return FQOne.MulBits(newB)
}

var qMinus1Over2, _ = new(big.Int).SetString("2001204777610833696708894912867952078278441409969503942666029068062015825245418932221343814564507832018947136279893", 10)

// LegendreSymbol is the legendre symbol of an element.
type LegendreSymbol uint8

const (
	// LegendreZero is the legendre symbol of zero.
	LegendreZero = LegendreSymbol(iota)

	// LegendreQuadraticResidue is the legendre symbol of quadratic residue.
	LegendreQuadraticResidue

	// LegendreQuadraticNonResidue is the legendre symbol of quadratic non-residue.
	LegendreQuadraticNonResidue
)

// Legendre gets the legendre symbol of the element.
func (f *FQ) Legendre() LegendreSymbol {
	o := f.Exp(qMinus1Over2)
	if o.IsZero() {
		return LegendreZero
	} else if o.Equals(FQOne) {
		return LegendreQuadraticResidue
	} else {
		return LegendreQuadraticNonResidue
	}
}

// RandFQ generates a random FQ element.
func RandFQ(reader io.Reader) (*FQ, error) {
	r, err := rand.Int(reader, QFieldModulus)
	if err != nil {
		return nil, err
	}
	return NewFQ(r), nil
}

// FQZero is the FQ at 0.
var FQZero = NewFQ(bigZero)

// FQOne is the FQ at 1.
var FQOne = NewFQ(bigOne)

// PP
func (f FQ) PP(indent int) string {
	spc := bytes.Repeat([]byte{' '}, indent)
	return fmt.Sprintf("%s%s\n", spc, f.String())
}
