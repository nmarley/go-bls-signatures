package bls

import (
	"errors"
	"fmt"
	"io"
	"math/big"
)

// G2Affine is an affine point on the G2 curve.
type G2Affine struct {
	x        *FQ2
	y        *FQ2
	infinity bool
}

// NewG2Affine constructs a new G2Affine point.
func NewG2Affine(x *FQ2, y *FQ2) *G2Affine {
	return &G2Affine{x: x, y: y, infinity: false}
}

// G2AffineZero represents the point at infinity on G2.
var G2AffineZero = &G2Affine{FQ2Zero, FQ2One, true}

var g2GeneratorXC1, _ = new(big.Int).SetString("3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758", 10)
var g2GeneratorXC0, _ = new(big.Int).SetString("352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160", 10)
var g2GeneratorYC1, _ = new(big.Int).SetString("927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582", 10)
var g2GeneratorYC0, _ = new(big.Int).SetString("1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905", 10)

// BCoeffFQ2 of the G2 curve.
var BCoeffFQ2 = NewFQ2(NewFQ(BCoeff), NewFQ(BCoeff))

// G2AffineOne represents the point at 1 on G2.
var G2AffineOne = &G2Affine{
	x: NewFQ2(
		NewFQ(g2GeneratorXC0),
		NewFQ(g2GeneratorXC1),
	),
	y: NewFQ2(
		NewFQ(g2GeneratorYC0),
		NewFQ(g2GeneratorYC1),
	), infinity: false}

func (g G2Affine) String() string {
	if g.infinity {
		return fmt.Sprintf("G2(Infinity)")
	}
	return fmt.Sprintf("G2Affine(x=%s, y=%s)", g.x, g.y)
}

// Copy returns a copy of the G2Affine point.
func (g G2Affine) Copy() *G2Affine {
	return &G2Affine{g.x.Copy(), g.y.Copy(), g.infinity}
}

// IsZero checks if the point is infinity.
func (g G2Affine) IsZero() bool {
	return g.infinity
}

// Neg negates the point.
func (g G2Affine) Neg() *G2Affine {
	if !g.IsZero() {
		return NewG2Affine(g.x, g.y.Neg())
	}
	return g.Copy()
}

// NegAssign negates the point.
func (g G2Affine) NegAssign() {
	if !g.IsZero() {
		g.y.NegAssign()
	}
}

// ToProjective converts an affine point to a projective one.
func (g G2Affine) ToProjective() *G2Projective {
	if g.IsZero() {
		return G2ProjectiveZero.Copy()
	}
	return NewG2Projective(g.x, g.y, FQ2One)
}

// Mul performs a EC multiply operation on the point.
func (g *G2Affine) Mul(b *big.Int) *G2Projective {
	bs := b.Bytes()
	res := G2ProjectiveZero.Copy()
	for i := uint(0); i < uint((b.BitLen()+7)/8)*8; i++ {
		part := i / 8
		bit := 7 - i%8
		o := bs[part]&(1<<(bit)) > 0
		res = res.Double()
		if o {
			res = res.AddAffine(g)
		}
	}
	return res
}

// IsOnCurve checks if a point is on the G2 curve.
func (g G2Affine) IsOnCurve() bool {
	if g.infinity {
		return true
	}
	y2 := g.y.Square()
	x3b := g.x.Square().Mul(g.x).Add(BCoeffFQ2)

	return y2.Equals(x3b)
}

// G2 cofactor = (x^8 - 4 x^7 + 5 x^6) - (4 x^4 + 6 x^3 - 4 x^2 - 4 x + 13) // 9
var g2Cofactor, _ = new(big.Int).SetString("305502333931268344200999753193121504214466019254188142667664032982267604182971884026507427359259977847832272839041616661285803823378372096355777062779109", 10)

// ScaleByCofactor scales the G2Affine point by the cofactor.
func (g G2Affine) ScaleByCofactor() *G2Projective {
	return g.Mul(g2Cofactor)
}

// Equals checks if two affine points are equal.
func (g G2Affine) Equals(other *G2Affine) bool {
	return (g.infinity == other.infinity) || (g.x.Equals(other.x) && g.y.Equals(other.y))
}

// GetG2PointFromX attempts to reconstruct an affine point given
// an x-coordinate. The point is not guaranteed to be in the subgroup.
// If and only if `greatest` is set will the lexicographically
// largest y-coordinate be selected.
func GetG2PointFromX(x *FQ2, greatest bool) *G2Affine {
	x3b := x.Square().Mul(x).Add(BCoeffFQ2)

	y := x3b.Sqrt()

	if y == nil {
		return nil
	}

	negY := y.Neg()

	yVal := negY
	if (y.Cmp(negY) < 0) != greatest {
		yVal = y
	}
	return NewG2Affine(x, yVal)
}

// SerializeBytes returns the serialized bytes for the points represented.
func (g *G2Affine) SerializeBytes() []byte {
	out := [192]byte{}

	copy(out[0:48], g.x.c0.n.Bytes())
	copy(out[48:96], g.x.c1.n.Bytes())
	copy(out[96:144], g.y.c0.n.Bytes())
	copy(out[144:192], g.y.c1.n.Bytes())

	return out[:]
}

// SetRawBytes sets the coords given the serialized bytes.
func (g *G2Affine) SetRawBytes(uncompressed []byte) {
	g.x = &FQ2{
		c0: &FQ{n: new(big.Int).SetBytes(uncompressed[0:48])},
		c1: &FQ{n: new(big.Int).SetBytes(uncompressed[48:96])},
	}
	g.y = &FQ2{
		c0: &FQ{n: new(big.Int).SetBytes(uncompressed[96:144])},
		c1: &FQ{n: new(big.Int).SetBytes(uncompressed[144:192])},
	}
	return
}

// DecompressG2 decompresses a G2 point from a big int and checks
// if it is in the correct subgroup.
func DecompressG2(b *big.Int) (*G2Affine, error) {
	affine, err := DecompressG2Unchecked(b)
	if err != nil {
		return nil, err
	}

	if !affine.IsInCorrectSubgroupAssumingOnCurve() {
		return nil, errors.New("point is not in correct subgroup")
	}
	return affine, nil
}

// DecompressG2Unchecked decompresses a G2 point from a big int.
func DecompressG2Unchecked(b *big.Int) (*G2Affine, error) {
	// Get a byte buffer from the passed integer
	buf := [G2ElementSize]byte{}
	copyBytes := b.Bytes()

	// TODO BLAH, fix this shit...
	copy(buf[G2ElementSize-len(copyBytes):], copyBytes)

	// Save bit1 for determining y coord later
	bit1 := (buf[0] & 0x80) > 0

	// Mask away (set to zero) the 3 most significant bits, since only 381 out
	// of 384 will be used for the x-coordinate, leaving the remaining 3.
	buf[0] &= 0x1f

	// The first G1ElementSize bytes are the C0 part of the FQ2
	xC0 := NewFQ(new(big.Int).SetBytes(buf[0:G1ElementSize]))

	// The second G1ElementSize bytes are the C1 part of the FQ2
	xC1 := NewFQ(new(big.Int).SetBytes(buf[G1ElementSize:G2ElementSize]))

	// Now create the full FQ2 with both parts
	x := NewFQ2(xC0, xC1)

	// Attempt to recover the Y coordinate and return the G2Affine point.
	return GetG2PointFromX(x, bit1), nil
}

// CompressG2 compresses a G2 point into a byte slice.
//
// Per the Chia spec, set the leftmost bit iff negative y. The other two unused
// bits are not used.
func CompressG2(affine *G2Affine) []byte {
	// Create a byte array big enough to hold both 381-bit points
	buf := [G2ElementSize]byte{}

	// Convert x-coord to byte slice
	x_C0 := affine.x.c0.n.Bytes()
	x_C1 := affine.x.c1.n.Bytes()

	// Copy c0 value into byte buffer
	// There is a more detailed explanation in CompressG1
	copy(buf[G1ElementSize-len(x_C0):], x_C0)
	// Copy c1 value into byte buffer
	copy(buf[G2ElementSize-len(x_C1):], x_C1)

	// Right shift the Q bits once to get Half Q
	halfQ := new(big.Int).Rsh(QFieldModulus, 1)

	// If the y coordinate is the bigger one of the two, set the first
	// bit to 1.
	if affine.y.c1.n.Cmp(halfQ) == 1 {
		buf[0] |= 0x80
	}

	return buf[0:G2ElementSize]
}

// IsInCorrectSubgroupAssumingOnCurve checks if the point multiplied by the
// field characteristic equals zero.
func (g G2Affine) IsInCorrectSubgroupAssumingOnCurve() bool {
	return g.Mul(frChar).IsZero()
}

// G2Projective is a projective point on the G2 curve.
type G2Projective struct {
	x *FQ2
	y *FQ2
	z *FQ2
}

// NewG2Projective creates a new G2Projective point.
func NewG2Projective(x *FQ2, y *FQ2, z *FQ2) *G2Projective {
	return &G2Projective{x, y, z}
}

// G2ProjectiveZero is the point at infinity where Z = 0.
var G2ProjectiveZero = &G2Projective{FQ2Zero, FQ2One, FQ2Zero}

// G2ProjectiveOne is the generator point on G2.
var G2ProjectiveOne = G2AffineOne.ToProjective()

func (g G2Projective) String() string {
	return fmt.Sprintf("G2Projective(x=%s, y=%s, z=%s)", g.x, g.y, g.z)
}

// Copy returns a copy of the G2Projective point.
func (g G2Projective) Copy() *G2Projective {
	return NewG2Projective(g.x.Copy(), g.y.Copy(), g.z.Copy())
}

// IsZero checks if the G2Projective point is zero.
func (g G2Projective) IsZero() bool {
	return g.z.IsZero()
}

// Equal checks if two projective points are equal.
func (g G2Projective) Equal(other *G2Projective) bool {
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

// ToAffine converts a G2Projective point to affine form.
func (g G2Projective) ToAffine() *G2Affine {
	if g.IsZero() {
		return G2AffineZero
	} else if g.z.IsZero() {
		return NewG2Affine(g.x, g.y)
	}

	// nonzero so must have an inverse
	zInv := g.z.Inverse()
	zInvSquared := zInv.Square()

	return NewG2Affine(g.x.Mul(zInvSquared), g.y.Mul(zInvSquared).Mul(zInv))
}

// Double performs EC doubling on the point.
//
// Jacobian elliptic curve point doubling
// http://www.hyperelliptic.org/EFD/oldefd/jacobian.html
func (g *G2Projective) Double() *G2Projective {
	if g.IsZero() {
		return g.Copy()
	}

	// A = x1^2
	a := g.x.Copy().Square()

	// B = y1^2
	b := g.y.Copy().Square()

	// C = B^2
	c := b.Copy().Square()

	// D = 2*((X1+B)^2-A-C)
	d := g.x.Copy().Add(b)
	d.SquareAssign()
	d.SubAssign(a)
	d.SubAssign(c)
	d.DoubleAssign()

	// E = 3*A
	e := a.Copy().Double()
	e.AddAssign(a)

	// F = E^2
	f := e.Copy().Square()

	// z3 = 2*Y1*Z1
	newZ := g.z.Copy().Mul(g.y)
	newZ.DoubleAssign()

	// x3 = F-2*D
	newX := f.Copy().Sub(d)
	newX.SubAssign(d)

	c.DoubleAssign()
	c.DoubleAssign()
	c.DoubleAssign()

	newY := d.Sub(newX)
	newY.MulAssign(e)
	newY.SubAssign(c)

	return NewG2Projective(newX, newY, newZ)
}

//def double_point_jacobian(p1, ec=default_ec, FE=Fq):
//    """
//    Jacobian elliptic curve point doubling
//    http://www.hyperelliptic.org/EFD/oldefd/jacobian.html
//    """
//    X, Y, Z = p1.x, p1.y, p1.z
//    if Y == FE.zero(ec.q) or p1.infinity:
//        return JacobianPoint(FE.one(ec.q), FE.one(ec.q),
//                             FE.zero(ec.q), True, ec)
//
//    # S = 4*X*Y^2
//    S = 4 * X * Y * Y
//
//    Z_sq = Z * Z
//    Z_4th = Z_sq * Z_sq
//    Y_sq = Y * Y
//    Y_4th = Y_sq * Y_sq
//
//    # M = 3*X^2 + a*Z^4
//    M = 3 * X * X
//    M += ec.a * Z_4th
//
//    # X' = M^2 - 2*S
//    X_p = M * M - 2 * S
//    # Y' = M*(S - X') - 8*Y^4
//    Y_p = M * (S - X_p) - 8 * Y_4th
//    # Z' = 2*Y*Z
//    Z_p = 2 * Y * Z
//    return JacobianPoint(X_p, Y_p, Z_p, False, ec)

// Add performs an EC Add operation with another point.
// Jacobian elliptic curve point addition
// http://www.hyperelliptic.org/EFD/oldefd/jacobian.html
func (g *G2Projective) Add(other *G2Projective) *G2Projective {
	if g.IsZero() {
		return other.Copy()
	}
	if other.IsZero() {
		return g.Copy()
	}

	// U1 = X1*Z2^2
	u1 := g.x.Mul(other.z.Square())

	// U2 = X2*Z1^2
	u2 := other.x.Mul(g.z.Square())

	// S1 = Y1*Z2^3
	s1 := g.y.Mul(other.z.Square().Mul(other.z))

	// S2 = Y2*Z1^3
	s2 := other.y.Mul(g.z.Square().Mul(g.z))

	if u1.Equals(u2) {
		if !s1.Equals(s2) {
			return NewG2Projective(FQ2One, FQ2One, FQ2Zero)
		} else {
			return g.Double()
		}
	}

	// H = U2 - U1
	h := u2.Sub(u1)

	// R = S2 - S1
	r := s2.Sub(s1)

	//H_sq = H * H
	h_sq := h.Square()

	//H_cu = H * H_sq
	h_cu := h_sq.Mul(h)

	// X3 = R^2 - H^3 - 2*U1*H^2
	x3 := r.Square().Sub(h_cu).Sub(u1.Mul(h_sq).MulInt(bigTwo))

	// Y3 = R*(U1*H^2 - X3) - S1*H^3
	y3 := r.Mul(u1.Mul(h_sq).Sub(x3)).Sub(s1.Mul(h_cu))

	// Z3 = H*Z1*Z2
	z3 := h.Mul(g.z).Mul(other.z)

	return NewG2Projective(x3, y3, z3)
}

// AddAffine performs an EC Add operation with an affine point.
func (g G2Projective) AddAffine(other *G2Affine) *G2Projective {
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
	hh := u2.Copy().Square()

	// I = 4*HH
	i := hh.Copy().Double()
	i.DoubleAssign()

	// J = H * I
	j := u2.Copy().Mul(i)

	// r = 2*(S2-Y1)
	s2.SubAssign(g.y)
	s2.DoubleAssign()

	// v = X1*I
	v := g.x.Copy().Mul(i)

	// X3 = r^2 - J - 2*V
	newX := s2.Copy().Square()
	newX.SubAssign(j)
	newX.SubAssign(v)
	newX.SubAssign(v)

	// Y3 = r*(V - X3) - 2*Y1*J
	newY := v.Copy().Sub(newX)
	newY.MulAssign(s2)
	i0 := g.y.Copy().Mul(j)
	i0.DoubleAssign()
	newY.SubAssign(i0)

	// Z3 = (Z1+H)^2 - Z1Z1 - HH
	newZ := g.z.Copy().Add(u2)
	newZ.SquareAssign()
	newZ.SubAssign(z1z1)
	newZ.SubAssign(hh)

	return NewG2Projective(newX, newY, newZ)
}

// Mul performs a EC multiply operation on the point.
// Double and add:
// https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication
func (g *G2Projective) Mul(n *big.Int) *G2Projective {
	// if p1.infinity or c % ec.q == 0:
	if g.IsZero() || new(big.Int).Mod(n, QFieldModulus).Cmp(bigZero) == 0 {
		return NewG2Projective(FQ2One, FQ2One, FQ2Zero)
	}

	addend := g.Copy()
	result := NewG2Projective(FQ2One, FQ2One, FQ2Zero)

	// while n > 0:
	for n.Cmp(bigZero) > 0 {
		// if n is odd
		if n.Bit(0) == 1 {
			//	result += addend
			result = result.Add(addend)
		}
		// double point
		addend = addend.Double()
		// c = c >> 1
		n = new(big.Int).Rsh(n, 1)
	}

	return result
}

var blsX, _ = new(big.Int).SetString("d201000000010000", 16)

const blsIsNegative = true

// G2Prepared is a prepared G2 point multiplication by blsX.
type G2Prepared struct {
	coeffs   [][3]*FQ2
	infinity bool
}

// IsZero checks if the point is at infinity.
func (g G2Prepared) IsZero() bool {
	return g.infinity
}

// G2AffineToPrepared performs multiplication of the affine point by blsX.
func G2AffineToPrepared(q *G2Affine) *G2Prepared {
	if q.IsZero() {
		return &G2Prepared{infinity: true}
	}

	doublingStep := func(r *G2Projective) (*FQ2, *FQ2, *FQ2) {
		tmp0 := r.x.Square()
		tmp1 := r.y.Square()
		tmp2 := tmp1.Square()
		tmp3 := tmp1.Add(r.x).Square().Sub(tmp0).Sub(tmp2).Double()
		tmp4 := tmp0.Double().Add(tmp0)
		tmp6 := r.x.Add(tmp4)
		tmp5 := tmp4.Square()
		zSquared := r.z.Square()
		r.x = tmp5.Sub(tmp3)
		r.x.SubAssign(tmp3)
		r.z = r.z.Add(r.y)
		r.z.SquareAssign()
		r.z.SubAssign(tmp1)
		r.z.SubAssign(zSquared)
		r.y = tmp3.Sub(r.x)
		r.y.MulAssign(tmp4)
		tmp2.DoubleAssign()
		tmp2.DoubleAssign()
		tmp2.DoubleAssign()
		r.y = r.y.Sub(tmp2)
		tmp3 = tmp4.Mul(zSquared)
		tmp3.DoubleAssign()
		tmp3.NegAssign()
		tmp6 = tmp6.Square()
		tmp6.SubAssign(tmp0)
		tmp6.SubAssign(tmp5)
		tmp1 = tmp1.Double()
		tmp1.DoubleAssign()
		tmp6 = tmp6.Sub(tmp1)
		tmp0 = r.z.Mul(zSquared)
		tmp0.DoubleAssign()
		return tmp0, tmp3, tmp6
	}

	additionStep := func(r *G2Projective, q *G2Affine) (*FQ2, *FQ2, *FQ2) {
		zSquared := r.z.Square()
		ySquared := q.y.Square()
		t0 := zSquared.Mul(q.x)
		t1 := q.y.Add(r.z)
		t1.SquareAssign()
		t1.SubAssign(ySquared)
		t1.SubAssign(zSquared)
		t1.MulAssign(zSquared)
		t2 := t0.Sub(r.x)
		t3 := t2.Square()
		t4 := t3.Double()
		t4.DoubleAssign()
		t5 := t4.Mul(t2)
		t6 := t1.Sub(r.y)
		t6.SubAssign(r.y)
		t9 := t6.Mul(q.x)
		t7 := t4.Mul(r.x)
		r.x = t6.Square()
		r.x.SubAssign(t5)
		r.x.SubAssign(t7)
		r.x.SubAssign(t7)
		r.z = r.z.Add(t2)
		r.z.SquareAssign()
		r.z.SubAssign(zSquared)
		r.z.SubAssign(t3)
		t10 := q.y.Add(r.z)
		t8 := t7.Sub(r.x)
		t8.MulAssign(t6)
		t0 = r.y.Mul(t5)
		t0.DoubleAssign()
		r.y = t8.Sub(t0)
		t10 = t10.Square()
		t10.SubAssign(ySquared)
		t10.SubAssign(r.z.Square())
		t9 = t9.Double()
		t9.SubAssign(t10)
		t10 = r.z.Double()
		t6.NegAssign()
		t6.DoubleAssign()

		return t10, t6, t9
	}

	coeffs := [][3]*FQ2{}
	r := q.ToProjective()

	foundOne := false
	blsXLsh1 := new(big.Int).Rsh(blsX, 1)
	bs := blsXLsh1.Bytes()
	for i := uint(0); i < uint(len(bs)*8); i++ {
		segment := i / 8
		bit := 7 - i%8
		set := bs[segment]&(1<<bit) > 0
		if !foundOne {
			foundOne = set
			continue
		}

		o0, o1, o2 := doublingStep(r)

		coeffs = append(coeffs, [3]*FQ2{o0, o1, o2})

		if set {
			o0, o1, o2 := additionStep(r, q)
			coeffs = append(coeffs, [3]*FQ2{o0, o1, o2})
		}
	}
	o0, o1, o2 := doublingStep(r)

	coeffs = append(coeffs, [3]*FQ2{o0, o1, o2})

	return &G2Prepared{coeffs, false}
}

// RandG2 generates a random G2 element.
func RandG2(r io.Reader) (*G2Projective, error) {
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
		f, err := RandFQ2(r)
		if err != nil {
			return nil, err
		}
		p := GetG2PointFromX(f, greatest)
		if p == nil {
			continue
		}
		p1 := p.ScaleByCofactor()
		if !p.IsZero() {
			return p1, nil
		}
	}
}

var swencSqrtNegThree, _ = new(big.Int).SetString("1586958781458431025242759403266842894121773480562120986020912974854563298150952611241517463240701", 10)
var swencSqrtNegThreeMinusOneDivTwo, _ = new(big.Int).SetString("793479390729215512621379701633421447060886740281060493010456487427281649075476305620758731620350", 10)
var swencSqrtNegThreeFQ2 = NewFQ2(NewFQ(swencSqrtNegThree), FQZero.Copy())
var swencSqrtNegThreeMinusOneDivTwoFQ2 = NewFQ2(NewFQ(swencSqrtNegThreeMinusOneDivTwo), FQZero.Copy())

// SWEncodeG2 implements the Shallue-van de Woestijne encoding.
func SWEncodeG2(t *FQ2) *G2Affine {
	// fmt.Println("NGM in SWEncodeG2")
	if t.IsZero() {
		// fmt.Println("NGM t.IsZero(), see-ya")
		return G2AffineZero.Copy()
	}

	parity := t.Parity()
	// fmt.Println("NGM parity:", parity)

	// w = t^2 + b + 1
	w := t.Square()
	w.AddAssign(BCoeffFQ2)
	w.AddAssign(FQ2One)

	// fmt.Println("NGM w:", w)

	// TODO: Look into this case... (differs from Python impl)
	if w.IsZero() {
		// fmt.Println("NGM w.IsZero()")
		ret := G2AffineOne.Copy()
		if parity {
			// NGM here
			// fmt.Println("here1")
			ret.NegAssign()
			// fmt.Println("here2")
		}
		return ret
	}

	// fmt.Println("NGM AFTER w.IsZero()")
	// w = ~w * sqrt(-3) * t
	w.InverseAssign()
	// fmt.Println("NGM ~w:", w)

	w.MulAssign(swencSqrtNegThreeFQ2)
	w.MulAssign(t)
	// fmt.Println("NGM w post sqrt(-3):", w)

	x1 := w.Mul(t)
	x1.NegAssign()
	x1.AddAssign(swencSqrtNegThreeMinusOneDivTwoFQ2)
	// fmt.Println("NGM x1:", x1)
	if p := GetG2PointFromX(x1, parity); p != nil {
		// fmt.Println("NGM returning point from x1")
		return p
	}

	x2 := x1.Neg()
	x2.SubAssign(FQ2One)
	// fmt.Println("NGM x2:", x2)
	if p := GetG2PointFromX(x2, parity); p != nil {
		// fmt.Println("NGM returning point from x2")
		return p
	}

	x3 := w.Square()
	x3.InverseAssign()
	x3.AddAssign(FQ2One)
	// fmt.Println("NGM x3:", x3)
	// fmt.Println("NGM returning point from x3")
	return GetG2PointFromX(x3, parity)
}

//// HashG2 converts a message to a point on the G2 curve.
//func HashG2(msg []byte, domain uint64) *G2Projective {
//	domainBytes := [8]byte{}
//	binary.BigEndian.PutUint64(domainBytes[:], domain)
//
//	hasher0, _ := blake2b.New(64, nil)
//	hasher0.Write(domainBytes[:])
//	hasher0.Write([]byte("G2_0"))
//	hasher0.Write(msg)
//	hasher1, _ := blake2b.New(64, nil)
//	hasher1.Write(domainBytes[:])
//	hasher1.Write([]byte("G2_1"))
//	hasher1.Write(msg)
//
//	xRe := HashFQ(hasher0)
//	xIm := HashFQ(hasher1)
//
//	xCoordinate := NewFQ2(xRe, xIm)
//
//	for {
//		yCoordinateSquared := xCoordinate.Copy()
//		yCoordinateSquared.Square()
//		yCoordinateSquared.Mul(yCoordinateSquared)
//
//		yCoordinateSquared.AddAssign(BCoeffFQ2)
//
//		yCoordinate := yCoordinateSquared.Sqrt()
//		if yCoordinate != nil {
//			return NewG2Affine(xCoordinate, yCoordinate).ScaleByCofactor()
//		}
//		xCoordinate.AddAssign(FQ2One)
//	}
//}

// HashG2 maps any string to a deterministic random point in G2.
func HashG2(msg []byte) *G2Projective {
	// h <- hash256(m)
	h := Hash256(msg)
	return HashG2PreHashed(h)
}

// HashG2PreHashed maps a prehashed message to a deterministic random point in G2.
func HashG2PreHashed(h []byte) *G2Projective {
	//t00 <- hash512(h + b"G2_0_c0") % q
	t00 := new(big.Int).Mod(
		new(big.Int).SetBytes(Hash512(append(h, []byte("G2_0_c0")...))),
		QFieldModulus,
	)
	//fmt.Printf("NGM t00 = %096x\n", t00)

	//t01 <- hash512(h + b"G2_0_c1") % q
	t01 := new(big.Int).Mod(
		new(big.Int).SetBytes(Hash512(append(h, []byte("G2_0_c1")...))),
		QFieldModulus,
	)
	//fmt.Printf("NGM t01 = %096x\n", t01)

	//t10 <- hash512(h + b"G2_1_c0") % q
	t10 := new(big.Int).Mod(
		new(big.Int).SetBytes(Hash512(append(h, []byte("G2_1_c0")...))),
		QFieldModulus,
	)
	//fmt.Printf("NGM t10 = %096x\n", t10)

	//t11 <- hash512(h + b"G2_1_c1") % q
	t11 := new(big.Int).Mod(
		new(big.Int).SetBytes(Hash512(append(h, []byte("G2_1_c1")...))),
		QFieldModulus,
	)
	//fmt.Printf("NGM t11 = %096x\n", t11)

	//t0 <- Fq2(t00, t01)
	t0 := NewFQ2(NewFQ(t00), NewFQ(t01))
	//fmt.Println("NGM t0 = ", t0.Serialize())

	//t1 <- Fq2(t10, t11)
	t1 := NewFQ2(NewFQ(t10), NewFQ(t11))
	//fmt.Println("NGM t1 = ", t1.Serialize())

	//p <- swEncode(t0) * swEncode(t1)
	t0Affine := SWEncodeG2(t0)
	//fmt.Println("NGM t0Affine:", t0Affine)
	//fmt.Printf("NGM t0Affine: %0192x\n", t0Affine.SerializeBytes())

	t1Affine := SWEncodeG2(t1)
	//fmt.Printf("NGM t1Affine: %0192x\n", t1Affine.SerializeBytes())

	p := t0Affine.ToProjective()
	// fmt.Println("NGM res", res)
	p = p.AddAffine(t1Affine)
	// fmt.Println("NGM res2", res)

	// Map to the r-torsion by raising to cofactor power
	// Described in page 11 of "Efficient hash maps to G2 on BLS curves" by Budroni and Pintore.
	//x <- abs(x)

	//x := blsX
	//fmt.Println("NGM(XHashG2) x:", x)

	p2 := p.Double()
	//fmt.Println("NGM(XHashG2) p2:", p2)

	innerPsi := p2.ToAffine().Psi()
	//fmt.Println("NGM(XHashG2) inner_psi:", inner_psi)

	psi2P := innerPsi.Psi()
	//fmt.Println("NGM(hash) outer_psi:", psi2P)

	// Mul performs a EC multiply operation on the point.
	// func (g G2Affine) Mul(b *big.Int) *G2Projective
	// t0_ := x * p
	t0_ := p.Mul(blsX)
	//fmt.Println("NGM(XHashG2) t0_:", t0_)

	// x.Exp(x, 2, nil).Add(x).Sub(1)
	//return p ^ (x^2 + x - 1) - psi(p ^ (x + 1)) + psi(psi(p ^ 2))
	t1_ := t0_.Mul(blsX)
	//fmt.Println("NGM(XHashG2) t1_:", t1_)

	t2_ := t0_.Add(t1_).AddAffine(p.ToAffine().Neg())
	//fmt.Println("NGM(XHashG2) t2_:", t2_)

	//t3 = psi((x+1) * P, ec)
	x1 := new(big.Int).Add(blsX, bigOne)
	t3_ := p.Mul(x1).ToAffine().Psi().ToProjective()
	//fmt.Println("NGM(XHashG2) t3_:", t3_)

	//rv = t2 - t3 + psi2P
	rv := t2_.AddAffine(t3_.ToAffine().Neg()).AddAffine(psi2P)
	//fmt.Println("NGM(XHashG2) rv:", rv.ToAffine())

	// Map to the r-torsion by raising to cofactor power
	return rv
}

// Untwist ...
//
// Given a point on G2 on the twisted curve, this converts it's
// coordinates back from Fq2 to Fq12. See Craig Costello book, look
// up twists.
func (g *G2Affine) Untwist() *Fq12Pair {
	FQ12OneRoot := NewFQ6(FQ2Zero, FQ2One, FQ2Zero)

	wsq := NewFQ12(FQ12OneRoot, FQ6Zero)
	nwsq := wsq.Inverse()

	wcu := NewFQ12(FQ6Zero, FQ12OneRoot)
	nwcu := wcu.Inverse()

	newX := NewFQ12(
		NewFQ6(
			FQ2Zero,
			FQ2Zero,
			nwsq.c0.c2.Mul(g.x),
		),
		FQ6Zero,
	)
	newY := NewFQ12(
		FQ6Zero,
		NewFQ6(
			FQ2Zero,
			nwcu.c1.c1.Mul(g.y),
			FQ2Zero,
		),
	)
	return NewFq12Pair(newX, newY)
}

// Psi ...
func (g *G2Affine) Psi() *G2Affine {
	ut := g.Untwist()

	t := NewFq12Pair(ut.x.FrobeniusMap(1), ut.y.FrobeniusMap(1))

	t2 := Twist(t)

	return NewG2Affine(t2.x, t2.y)
}

// TODO: Move to FQ12 ?

// Fq12Pair
// Not sure what to call this, it's a x/y pairing of FQ12 fields
type Fq12Pair struct {
	x *FQ12
	y *FQ12
}

func NewFq12Pair(x, y *FQ12) *Fq12Pair {
	return &Fq12Pair{x, y}
}

func (f Fq12Pair) String() string {
	return fmt.Sprintf("Fq12Pair(x=%s, y=%s)", f.x, f.y)
}

func (f Fq12Pair) PP() string {
	return fmt.Sprintf("Fq12Pair(\nx=%s, y=%s\n)", f.x.PP(), f.y.PP())
}

// Conjugate returns the conjugate of the Fq12Pair
func (f *Fq12Pair) Conjugate() *Fq12Pair {
	return NewFq12Pair(f.x, f.y.Neg())
}

// Equal returns whether the Fq12Pair is equal
func (f *Fq12Pair) Equal(other *Fq12Pair) bool {
	return f.x.Equals(other.x) && f.y.Equals(other.y)
}

// End Fq12Pair

// Twist ...
//
// Given an untwisted point, this converts it's
// coordinates to a point on the twisted curve. See Craig Costello
// book, look up twists.
// func Twist(pair *Fq12Pair) []*FQ2 {
func Twist(pair *Fq12Pair) *G2Affine {
	// TODO: Could move this to FQ12 also
	FQ12OneRoot := NewFQ6(FQ2Zero, FQ2One, FQ2Zero)

	// TODO: hard-code these values, they are constant
	wsq := NewFQ12(FQ12OneRoot, FQ6Zero)
	wcu := NewFQ12(FQ6Zero, FQ12OneRoot)

	newX := wsq.Mul(pair.x)
	newY := wcu.Mul(pair.y)

	return NewG2Affine(newX.c0.c0, newY.c0.c0)
}

// PP ...
func (g G2Projective) PP() string {
	if g.IsZero() {
		return g.String()
	}

	return fmt.Sprintf("G2Projective(x=%s, y=%s, z=%s)", g.x.PP(4), g.y.PP(4), g.z.PP(4))
}

// PP ...
func (g G2Affine) PP() string {
	if g.IsZero() {
		return g.String()
	}

	return fmt.Sprintf("G2Affine(x=%s, y=%s)", g.x, g.y)
}
