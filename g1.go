package bls

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/blake2b"
)

// G1Affine is an affine point on the G1 curve.
type G1Affine struct {
	x        *FQ
	y        *FQ
	infinity bool
}

// NewG1Affine constructs a new G1Affine point.
func NewG1Affine(x *FQ, y *FQ) *G1Affine {
	return &G1Affine{x: x, y: y, infinity: false}
}

// G1AffineZero represents the point at infinity on G1.
var G1AffineZero = &G1Affine{FQZero, FQOne, true}

var g1GeneratorX, _ = new(big.Int).SetString("3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507", 10)
var g1GeneratorY, _ = new(big.Int).SetString("1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569", 10)

// BCoeff of the G1 curve.
var BCoeff = big.NewInt(4)

// G1AffineOne represents the point at 1 on G1.
var G1AffineOne = &G1Affine{NewFQ(g1GeneratorX), NewFQ(g1GeneratorY), false}

func (g G1Affine) String() string {
	if g.infinity {
		return fmt.Sprintf("G1(infinity)")
	}
	return fmt.Sprintf("G1Affine(x=%s, y=%s)", g.x, g.y)
}

// Copy returns a copy of the G1Affine point.
func (g G1Affine) Copy() *G1Affine {
	return &G1Affine{g.x.Copy(), g.y.Copy(), g.infinity}
}

// IsZero checks if the point is infinity.
func (g G1Affine) IsZero() bool {
	return g.infinity
}

// Neg negates the point.
func (g G1Affine) Neg() *G1Affine {
	if !g.IsZero() {
		return NewG1Affine(g.x, g.y.Neg())
	}
	return g.Copy()
}

// NegAssign negates the point.
func (g G1Affine) NegAssign() {
	if !g.IsZero() {
		g.y.NegAssign()
	}
}

// ToProjective converts an affine point to a projective one.
func (g G1Affine) ToProjective() *G1Projective {
	if g.IsZero() {
		return G1ProjectiveZero
	}
	return NewG1Projective(g.x, g.y, FQOne)
}

// Mul performs a EC multiply operation on the point.
func (g G1Affine) Mul(b *big.Int) *G1Projective {
	bs := b.Bytes()
	res := G1ProjectiveZero.Copy()
	for i := uint(0); i < uint((b.BitLen()+7)/8)*8; i++ {
		part := i / 8
		bit := 7 - i%8
		o := bs[part]&(1<<(bit)) > 0
		res = res.Double()
		if o {
			res = res.AddAffine(&g)
		}
	}
	return res
}

// IsOnCurve checks if a point is on the G1 curve.
func (g G1Affine) IsOnCurve() bool {
	if g.infinity {
		return true
	}
	y2 := g.y.Square()
	x3b := g.x.Square().Mul(g.x).Add(NewFQ(BCoeff))

	return y2.Equals(x3b)
}

var frChar, _ = new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)

// IsInCorrectSubgroupAssumingOnCurve checks if the point multiplied by the
// field characteristic equals zero.
func (g G1Affine) IsInCorrectSubgroupAssumingOnCurve() bool {
	return g.Mul(frChar).IsZero()
}

// G1 cofactor = (x - 1)^2 / 3  = 76329603384216526031706109802092473003
var g1Cofactor, _ = new(big.Int).SetString("76329603384216526031706109802092473003", 10)

// ScaleByCofactor scales the G1Affine point by the cofactor.
func (g G1Affine) ScaleByCofactor() *G1Projective {
	return g.Mul(g1Cofactor)
}

// Equals checks if two affine points are equal.
func (g G1Affine) Equals(other *G1Affine) bool {
	return (g.infinity == other.infinity) || (g.x.Equals(other.x) && g.y.Equals(other.y))
}

// DecompressG1 decompresses the big int into an affine point and checks
// if it is in the correct prime group.
func DecompressG1(b *big.Int) (*G1Affine, error) {
	affine, err := DecompressG1Unchecked(b)
	if err != nil {
		return nil, err
	}

	if !affine.IsInCorrectSubgroupAssumingOnCurve() {
		return nil, errors.New("not in correct subgroup")
	}
	return affine, nil
}

// DecompressG1Unchecked decompresses the big int into an affine point without
// checking if it's in the correct prime group.
func DecompressG1Unchecked(b *big.Int) (*G1Affine, error) {
	buf := [G1ElementSize]byte{}
	copyBytes := new(big.Int).Set(b).Bytes()

	// Copy bytes...
	copy(buf[G1ElementSize-len(copyBytes):], copyBytes)

	// Save bit1 for y coord later
	bit1 := (buf[0] & 0x80) > 0
	buf[0] &= 0x1f

	x := NewFQ(new(big.Int).SetBytes(buf[:]))

	return GetG1PointFromX(x, bit1), nil
}

// GetG1PointFromX attempts to reconstruct an affine point given
// an x-coordinate. The point is not guaranteed to be in the subgroup.
// If and only if `greatest` is set will the lexicographically
// largest y-coordinate be selected.
func GetG1PointFromX(x *FQ, greatest bool) *G1Affine {
	x3b := x.Square().Mul(x).Add(NewFQ(BCoeff))

	y := x3b.Sqrt()

	if y == nil {
		return nil
	}

	negY := y.Neg()

	yVal := negY
	if (y.Cmp(negY) < 0) != greatest {
		yVal = y
	}
	return NewG1Affine(x, yVal)
}

// CompressG1 compresses a G1 point into a byte slice.
//
// Per the Chia spec, set the leftmost bit iff negative y. The other two unused
// bits are not used.
func CompressG1(g *G1Affine) []byte {
	// Convert x-coord to byte slice

	// Create a byte arry of exactly G1ElementSize bytes
	buf := [G1ElementSize]byte{}

	// Copy x-coord bytes into the byte array, but make sure and align them to
	// the right of the array. Meaning, if the integer backing the x-coord is
	// small, then there should be 0s at the front.
	//
	// Using an example with smaller numbers, let's say our x-coord is 7, but
	// we have a 2-byte array to hold it:
	//
	// n := 7
	// buf := [2]byte{}
	// copy(buf[:], n)  // <-- BUG!! This results in an array like [2]byte{0x7, 0x0}
	//                  //           What we *actually* want is:   [2]byte{0x0, 0x7}
	//
	// We want the starting index for copy destination to be the max array size
	// minus the length of the buffer we are copying. In this case, 2-len(n):
	//
	// copy(buf[2-len(n):], n)
	//
	// This results in what we want:  [2]byte{0x0, 0x7}
	//
	copyBytes := g.x.n.Bytes()
	copy(buf[G1ElementSize-len(copyBytes):], copyBytes)

	// Right shift the Q bits once to get Half Q
	halfQ := new(big.Int).Rsh(QFieldModulus, 1)

	// If the y coordinate is the bigger one of the two, set the first
	// bit to 1.
	if g.y.n.Cmp(halfQ) == 1 {
		buf[0] |= 0x80
	}

	return buf[0:G1ElementSize]
}

// G1Projective is a projective point on the G1 curve.
type G1Projective struct {
	x *FQ
	y *FQ
	z *FQ
}

// NewG1Projective creates a new G1Projective point.
func NewG1Projective(x *FQ, y *FQ, z *FQ) *G1Projective {
	return &G1Projective{x, y, z}
}

// G1ProjectiveZero is the point at infinity where Z = 0.
var G1ProjectiveZero = &G1Projective{FQZero, FQOne, FQZero}

// G1ProjectiveOne is the generator point on G1.
var G1ProjectiveOne = G1AffineOne.ToProjective()

func (g G1Projective) String() string {
	return fmt.Sprintf("G1Projective(x=%s, y=%s, z=%s)", g.x, g.y, g.z)
}

// Copy returns a copy of the G1Projective point.
func (g G1Projective) Copy() *G1Projective {
	return NewG1Projective(g.x.Copy(), g.y.Copy(), g.z.Copy())
}

// IsZero checks if the G1Projective point is zero.
func (g G1Projective) IsZero() bool {
	return g.z.IsZero()
}

// Equal checks if two projective points are equal.
func (g G1Projective) Equal(other *G1Projective) bool {
	if g.IsZero() {
		return other.IsZero()
	}
	if other.IsZero() {
		return false
	}

	z1 := g.z.Square()
	z2 := other.z.Square()

	tmp1 := g.x.Mul(z2)
	tmp2 := other.x.Mul(z1)
	if !tmp1.Equals(tmp2) {
		return false
	}

	return z1.Mul(g.z).Mul(other.y).Equals(z2.Mul(other.z).Mul(g.y))
}

// ToAffine converts a G1Projective point to affine form.
func (g G1Projective) ToAffine() *G1Affine {
	if g.IsZero() {
		return G1AffineZero
	} else if g.z.IsZero() {
		return NewG1Affine(g.x, g.y)
	}

	// nonzero so must have an inverse
	zInv := g.z.Inverse()
	zInvSquared := zInv.Square()

	return NewG1Affine(g.x.Mul(zInvSquared), g.y.Mul(zInvSquared).Mul(zInv))
}

// Double performs EC doubling on the point.
func (g G1Projective) Double() *G1Projective {
	if g.IsZero() {
		return g.Copy()
	}

	// A = x1^2
	a := g.x.Square()

	// B = y1^2
	b := g.y.Square()

	// C = B^2
	c := b.Square()

	// D = 2*((X1+B)^2-A-C)
	d := g.x.Add(b)
	d.SquareAssign()
	d.SubAssign(a)
	d.SubAssign(c)
	d.DoubleAssign()

	// E = 3*A
	e := a.Double()
	e.AddAssign(a)

	// F = E^2
	f := e.Square()

	// z3 = 2*Y1*Z1
	newZ := g.z.Mul(g.y)
	newZ.DoubleAssign()

	// x3 = F-2*D
	newX := f.Sub(d)
	newX.SubAssign(d)

	c.DoubleAssign()
	c.DoubleAssign()
	c.DoubleAssign()

	newY := d.Sub(newX)
	newY.MulAssign(e)
	newY.SubAssign(c)

	return NewG1Projective(newX, newY, newZ)
}

// Add performs an EC Add operation with another point.
// Jacobian elliptic curve point addition
// http://www.hyperelliptic.org/EFD/oldefd/jacobian.html
func (g *G1Projective) Add(other *G1Projective) *G1Projective {
	if g.IsZero() {
		return other.Copy()
	}
	if other.IsZero() {
		return g.Copy()
	}

	// U1 = X1*Z2^2
	u1 := g.x.Mul(other.z.Square())
	// fmt.Println("NGMgo u1:", u1)

	// U2 = X2*Z1^2
	u2 := other.x.Mul(g.z.Square())
	// 	fmt.Println("NGMgo u2:", u2)

	// S1 = Y1*Z2^3
	s1 := g.y.Mul(other.z.Square().Mul(other.z))
	// fmt.Println("NGMgo s1:", s1)

	// S2 = Y2*Z1^3
	s2 := other.y.Mul(g.z.Square().Mul(g.z))
	// fmt.Println("NGMgo s2:", s2)

	if u1.Equals(u2) {
		// fmt.Println("NGMgo u1.Equals(u2) (SIC)")
		if !s1.Equals(s2) {
			// fmt.Println("NGMgo NOT!!! s1.Equals(s2) (SIC)")
			return NewG1Projective(FQOne, FQOne, FQZero)
		} else {
			// fmt.Println("NGMgo Else double g (GG)")
			return g.Double()
		}
	}

	// H = U2 - U1
	h := u2.Sub(u1)
	// fmt.Println("NGMgo h:", h)

	// R = S2 - S1
	r := s2.Sub(s1)
	// fmt.Println("NGMgo r:", r)

	//H_sq = H * H
	h_sq := h.Square()
	// fmt.Println("NGMgo h_sq:", h_sq)

	//H_cu = H * H_sq
	h_cu := h_sq.Mul(h)
	// fmt.Println("NGMgo h_cu:", h_cu)

	// X3 = R^2 - H^3 - 2*U1*H^2
	x3 := r.Square().Sub(h_cu).Sub(u1.Add(u1).Mul(h_sq))

	// Y3 = R*(U1*H^2 - X3) - S1*H^3
	y3 := r.Mul(u1.Mul(h_sq).Sub(x3)).Sub(s1.Mul(h_cu))

	// Z3 = H*Z1*Z2
	z3 := h.Mul(g.z).Mul(other.z)

	return NewG1Projective(x3, y3, z3)
}

// AddAffine performs an EC Add operation with an affine point.
func (g G1Projective) AddAffine(other *G1Affine) *G1Projective {
	if g.IsZero() {
		return other.ToProjective()
	}
	if other.IsZero() {
		return g.Copy()
	}

	// Z1Z1 = Z1^2
	z1z1 := g.z.Square()

	// U2 = x2*Z1Z1
	u2 := other.x.Mul(z1z1)

	// S2 = Y2*Z1*Z1Z1
	s2 := other.y.Mul(g.z).Mul(z1z1)

	if g.x.Equals(u2) && g.y.Equals(s2) {
		// points are equal
		return g.Double()
	}

	// H = U2-X1
	u2.SubAssign(g.x)

	// HH = H^2
	hh := u2.Square()

	// I = 4*HH
	i := hh.Double()
	i.DoubleAssign()

	// J = H * I
	j := u2.Mul(i)

	// r = 2*(S2-Y1)
	s2.SubAssign(g.y)
	s2.DoubleAssign()

	// v = X1*I
	v := g.x.Mul(i)

	// X3 = r^2 - J - 2*V
	newX := s2.Square()
	newX.SubAssign(j)
	newX.SubAssign(v)
	newX.SubAssign(v)

	// Y3 = r*(V - X3) - 2*Y1*J
	newY := v.Sub(newX)
	newY.MulAssign(s2)
	i0 := g.y.Mul(j)
	i0.DoubleAssign()
	newY.SubAssign(i0)

	// Z3 = (Z1+H)^2 - Z1Z1 - HH
	newZ := g.z.Add(u2)
	newZ.SquareAssign()
	newZ.SubAssign(z1z1)
	newZ.SubAssign(hh)

	return NewG1Projective(newX, newY, newZ)
}

// Mul performs a EC multiply operation on the point.
// Double and add:
// https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication
func (g G1Projective) Mul(n *big.Int) *G1Projective {
	res := NewG1Projective(FQOne, FQOne, FQZero)
	if g.z.IsZero() || (new(big.Int).Mod(n, QFieldModulus).Cmp(bigZero) == 0) {
		return res
	}

	addend := g.Copy()

	fmt.Println("NGMgo res(initial):", res)
	fmt.Println("NGMgo addend(initial):", addend)

	// while n > 0:
	for n.Cmp(bigZero) > 0 {
		// if n is odd
		if n.Bit(0) == 1 {
			// res += addend
			fmt.Println("NGMgo rbef:", res)
			res = res.Add(addend)
			fmt.Println("NGMgo r+a:", res)
		}
		// Double point
		addend = addend.Double()
		fmt.Println("NGMgo a+a:", addend)
		// Shift bits right to halve n
		n.Rsh(n, 1)
	}

	fmt.Println("NGMgo res(final):", res)
	return res
}

// RandG1 generates a random G1 element.
func RandG1(r io.Reader) (*G1Projective, error) {
	for {
		b := make([]byte, 1)
		_, err := r.Read(b)
		if err != nil {
			return nil, err
		}
		greatest := false
		if b[0]%2 == 0 {
			greatest = true
		}
		f, err := RandFQ(r)
		if err != nil {
			return nil, err
		}
		p := GetG1PointFromX(f, greatest)
		if p == nil {
			continue
		}
		p1 := p.ScaleByCofactor()
		if !p.IsZero() {
			return p1, nil
		}
	}
}

// SWEncodeG1 implements the Shallue-van de Woestijne encoding.
func SWEncodeG1(t *FQ) *G1Affine {
	if t.IsZero() {
		return G1AffineZero.Copy()
	}

	parity := t.Parity()

	w := t.Square()
	w.AddAssign(NewFQ(BCoeff))
	w.AddAssign(FQOne)

	if w.IsZero() {
		ret := G1AffineOne.Copy()
		if parity {
			ret.Neg()
		}
		return ret
	}

	w = w.Inverse()
	w.MulAssign(NewFQ(swencSqrtNegThree))
	w.MulAssign(t)

	x1 := w.Mul(t)
	x1.NegAssign()
	x1.AddAssign(NewFQ(swencSqrtNegThreeMinusOneDivTwo))
	if p := GetG1PointFromX(x1, parity); p != nil {
		return p
	}

	x2 := x1.Neg()
	x2.SubAssign(FQOne)
	if p := GetG1PointFromX(x2, parity); p != nil {
		return p
	}

	x3 := w.Square()
	x3 = x3.Inverse()
	x3.AddAssign(FQOne)
	return GetG1PointFromX(x3, parity)
}

// HashG1 converts a message to a point on the G2 curve.
func HashG1(msg []byte, domain uint64) *G1Projective {
	domainBytes := [8]byte{}
	binary.BigEndian.PutUint64(domainBytes[:], domain)

	hasher0, _ := blake2b.New(64, nil)
	hasher0.Write(msg)
	hasher0.Write([]byte("G1_0"))
	hasher0.Write(domainBytes[:])
	hasher1, _ := blake2b.New(64, nil)
	hasher1.Write(msg)
	hasher1.Write([]byte("G1_1"))
	hasher1.Write(domainBytes[:])
	t0 := HashFQ(hasher0)
	t0Affine := SWEncodeG1(t0)
	t1 := HashFQ(hasher1)
	t1Affine := SWEncodeG1(t1)

	res := t0Affine.ToProjective()
	res = res.AddAffine(t1Affine)
	return res.ToAffine().ScaleByCofactor()
}

// XHashG1 converts a message to a point on the G1 curve.
func XHashG1(msg []byte) *G1Projective {
	// h <- hash256(m)
	h := Hash256(msg)

	// t0 <- hash512(h + b"G1_0") % q
	t0 := NewFQ(
		new(big.Int).Mod(
			new(big.Int).SetBytes(Hash512(append(h, []byte("G1_0")...))),
			QFieldModulus,
		),
	)
	t0Affine := SWEncodeG1(t0)

	// t1 <- hash512(h + b"G1_1") % q
	t1 := NewFQ(
		new(big.Int).Mod(
			new(big.Int).SetBytes(Hash512(append(h, []byte("G1_1")...))),
			QFieldModulus,
		),
	)
	t1Affine := SWEncodeG1(t1)

	// p <- swEncode(t0) * swEncode(t1)
	res := t0Affine.ToProjective()
	res = res.AddAffine(t1Affine)

	// Map to the r-torsion by raising to cofactor power
	// return p ^ h
	return res.ToAffine().ScaleByCofactor()
}

// PP ...
func (g G1Projective) PP() string {
	if g.IsZero() {
		return g.String()
	}

	return fmt.Sprintf("G1Projective(x=%s, y=%s, z=%s)", g.x, g.y, g.z)
}

// PP ...
func (g G1Affine) PP() string {
	if g.IsZero() {
		return g.String()
	}

	return fmt.Sprintf("G1Affine(x=%s, y=%s)", g.x, g.y)
}
