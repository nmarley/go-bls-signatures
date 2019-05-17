package bls_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/matryer/is"
	"gitlab.com/nmarley/go-bls-signatures"
)

func HexInt(hexStr string) *big.Int {
	n, _ := new(big.Int).SetString(hexStr, 16)
	return n
}
func TestG1ProjectiveMul(t *testing.T) {
	tests := []struct {
		pointX string
		pointY string
		pointZ string
		nHex   string
		resX   string
		resY   string
		resZ   string
	}{
		{
			pointX: "02a8d2aaa6a5e2e08d4b8d406aaf0121a2fc2088ed12431e6b0663028da9ac5922c9ea91cde7dd74b7d795580acc7a61",
			pointY: "0145bcfef3c097722ea4994dc043be38a47ca15cf0f7622286ba6f85c4b5ddd412c43042938ab6a2eafcaae38119e305",
			pointZ: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
			nHex:   "106d1d07cde836f9b30ef9f51a9184429444db20c43af947b8bbaa4ed49be142",
			resX:   "173ff35c6432c796bc1ebd58f1b40f77a56495c4bb5424de9dce8c0a6a24882457773340ee9fb80daa6d8620cc219407",
			resY:   "0b8bb2cd7c096e369ab0c95c051b7b48e2e1beefbe2d865f222d5aa5301c42774c43aa8377bf05f069a89a22472e3b10",
			resZ:   "03ad295d408411f54397ecd48518f0d8b769dbba5acecdae7d220a1b57653569384d85122455578264e2cc63a9b672a6",
		},
	}

	// NGMpy res: JacobianPoint(x=Fq(173ff35c6432c796bc1ebd58f1b40f77a56495c4bb5424de9dce8c0a6a24882457773340ee9fb80daa6d8620cc219407), y=Fq(0b8bb2cd7c096e369ab0c95c051b7b48e2e1beefbe2d865f222d5aa5301c42774c43aa8377bf05f069a89a22472e3b10), z=Fq(03ad295d408411f54397ecd48518f0d8b769dbba5acecdae7d220a1b57653569384d85122455578264e2cc63a9b672a6), i=False)

	for i, tt := range tests {
		t.Run(fmt.Sprintf("%d", i), func(st *testing.T) {
			is := is.New(st)

			point := bls.NewG1Projective(
				makeFQ(tt.pointX),
				makeFQ(tt.pointY),
				makeFQ(tt.pointZ),
			)

			n := HexInt(tt.nHex)

			resPoint := bls.NewG1Projective(
				makeFQ(tt.resX),
				makeFQ(tt.resY),
				makeFQ(tt.resZ),
			)

			res := point.Mul(n)
			is.Equal(res, resPoint)
		})
	}
}

func TestG1ProjectiveAdd(t *testing.T) {
	tests := []struct {
		p1x  string
		p1y  string
		p1z  string
		p2x  string
		p2y  string
		p2z  string
		resX string
		resY string
		resZ string
	}{
		{
			p1x: "01a89b5b9147007d2f6d05419c96928acbf319b5563c3f05a12ee0b11265d8d24e3fccd613ba5e4bc59d40d80d0cb734",
			p1y: "14fa6c10f0b6a3691f19d01560a410081b16486f49f03f8bafb45c149c5664b610494be7c234e674d9e1e4c45dd3ac5d",
			p1z: "028b79fde7812ee45d49329b80877c7148f942b9e1eec4450d74df0b896bbba82588608527156d45d5f955c70233c60a",

			p2x: "0241693bcdbbd80196f04dda45614cde8ce7830b67e160aa5d9865dc8da4eb868a49edaf0f47a8e5a9d6ea8674f2adec",
			p2y: "1465ed4d5ea6cefed637b0849112d1181b734354ebf5737be960a38c09a94fad3b0f7145dac1e4eaed1b25178756e7b4",
			p2z: "06d9b63732d28524ace23d230dfc5002194c7d2c26be6f4c7c86735f7c5896395e494f57c49811fa938077233b9387b7",

			resX: "157cab11ec3354b77ccce4cfa8a4063897f62d55b75a49f51fa568b09e4dbb87416987d4e65b145371586340eddd2520",
			resY: "025b922e4d1e76beb38b242c22d76c77d0daddac848e27dc3f16465005634f27ea64cc4101513df6207cb56f204250d0",
			resZ: "1223495578cfe0f0a9c2b09343931aa52d197f32ae098d63c1b2cb683ccf120be5691b24083b642060660489e81a0803",
		},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprintf("%d", i), func(st *testing.T) {
			is := is.New(st)

			p1 := bls.NewG1Projective(
				makeFQ(tt.p1x),
				makeFQ(tt.p1y),
				makeFQ(tt.p1z),
			)
			p2 := bls.NewG1Projective(
				makeFQ(tt.p2x),
				makeFQ(tt.p2y),
				makeFQ(tt.p2z),
			)

			expected := bls.NewG1Projective(
				makeFQ(tt.resX),
				makeFQ(tt.resY),
				makeFQ(tt.resZ),
			)

			res := p1.Add(p2)
			is.Equal(res, expected)
		})
	}
}

func TestG1PDouble(t *testing.T) {
	tests := []struct {
		p1x  string
		p1y  string
		p1z  string
		resX string
		resY string
		resZ string
	}{
		{
			p1x: "01a89b5b9147007d2f6d05419c96928acbf319b5563c3f05a12ee0b11265d8d24e3fccd613ba5e4bc59d40d80d0cb734",
			p1y: "14fa6c10f0b6a3691f19d01560a410081b16486f49f03f8bafb45c149c5664b610494be7c234e674d9e1e4c45dd3ac5d",
			p1z: "028b79fde7812ee45d49329b80877c7148f942b9e1eec4450d74df0b896bbba82588608527156d45d5f955c70233c60a",

			resX: "0ef5ad284432d0a5f4c1cecc515551729218c8c9c95da4d7e9811beee7f01a9bef91417129a23743c4b28d3339178812",
			resY: "1561294136e1612f7b0061e3ee2e04ea5a586c882d4f0ecd0e1a7fba22fc835f03fe4d0a4a0a83d385b9d88b335de657",
			resZ: "07b967b8c27e1e514acf46eedce8bb17628d6d0b7f84f26d9cd5d998b9ccb63f92405bdf50bad1cf8dd86a766800318f",
		},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprintf("%d", i), func(st *testing.T) {
			is := is.New(st)

			p1 := bls.NewG1Projective(
				makeFQ(tt.p1x),
				makeFQ(tt.p1y),
				makeFQ(tt.p1z),
			)

			expected := bls.NewG1Projective(
				makeFQ(tt.resX),
				makeFQ(tt.resY),
				makeFQ(tt.resZ),
			)

			res := p1.Double()
			is.Equal(res, expected)
		})
	}
}

func TestG1Generator(t *testing.T) {
	x := bls.FQZero.Copy()
	i := 0

	for {
		// y^2 = x^3 + b
		rhs := x.Square().Mul(x).Add(bls.NewFQ(bls.BCoeff))

		y := rhs.Sqrt()

		if y != nil {
			negY := y.Neg()
			pY := negY

			if y.Cmp(negY) < 0 {
				pY = y
			}

			p := bls.NewG1Affine(x, pY)

			if p.IsInCorrectSubgroupAssumingOnCurve() {
				t.Fatal("new point should be in subgroup")
			}

			g1 := p.ScaleByCofactor()

			if !g1.IsZero() {
				if i != 4 {
					t.Fatal("non-zero point should be 4th point")
				}

				g1 := g1.ToAffine()

				if !g1.IsInCorrectSubgroupAssumingOnCurve() {
					t.Fatal("point is not in correct subgroup")
				}

				if !g1.Equals(bls.G1AffineOne) {
					t.Fatal("point is not equal to generator point")
				}
				break
			}
		}

		i += 1
		x = x.Add(bls.FQOne)
	}
}

type XORShift struct {
	state uint64
}

func NewXORShift(state uint64) *XORShift {
	return &XORShift{state}
}

func (xor *XORShift) Read(b []byte) (int, error) {
	for i := range b {
		x := xor.state
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		b[i] = uint8(x)
		xor.state = x
	}
	return len(b), nil
}

const g1MulAssignSamples = 10

func BenchmarkG1MulAssign(b *testing.B) {
	type mulData struct {
		g *bls.G1Projective
		f *bls.FR
	}

	r := NewXORShift(1)
	inData := [g1MulAssignSamples]mulData{}
	for i := 0; i < g1MulAssignSamples; i++ {
		gx, _ := bls.RandFQ(r)
		gy, _ := bls.RandFQ(r)
		gz, _ := bls.RandFQ(r)
		randFR, _ := bls.RandFR(r)
		inData[i] = mulData{
			g: bls.NewG1Projective(gx, gy, gz),
			f: randFR,
		}
	}
	b.ResetTimer()

	count := 0
	for i := 0; i < b.N; i++ {
		inData[count].g.Mul(inData[count].f.ToBig())
		count = (count + 1) % g1MulAssignSamples
	}
}

func BenchmarkG1AddAssign(b *testing.B) {
	type addData struct {
		g1 *bls.G1Projective
		g2 *bls.G1Projective
	}

	r := NewXORShift(1)
	inData := [g1MulAssignSamples]addData{}
	for i := 0; i < g1MulAssignSamples; i++ {
		g1x, _ := bls.RandFQ(r)
		g1y, _ := bls.RandFQ(r)
		g1z, _ := bls.RandFQ(r)
		g2x, _ := bls.RandFQ(r)
		g2y, _ := bls.RandFQ(r)
		g2z, _ := bls.RandFQ(r)
		inData[i] = addData{
			g1: bls.NewG1Projective(g1x, g1y, g1z),
			g2: bls.NewG1Projective(g2x, g2y, g2z),
		}
	}
	b.ResetTimer()

	count := 0
	for i := 0; i < b.N; i++ {
		inData[count].g1.Add(inData[count].g2)
		count = (count + 1) % g1MulAssignSamples
	}
}

func BenchmarkG1AddAssignMixed(b *testing.B) {
	type addData struct {
		g1 *bls.G1Projective
		g2 *bls.G1Affine
	}

	r := NewXORShift(1)
	inData := [g1MulAssignSamples]addData{}
	for i := 0; i < g1MulAssignSamples; i++ {
		g1x, _ := bls.RandFQ(r)
		g1y, _ := bls.RandFQ(r)
		g1z, _ := bls.RandFQ(r)
		g2x, _ := bls.RandFQ(r)
		g2y, _ := bls.RandFQ(r)
		inData[i] = addData{
			g1: bls.NewG1Projective(g1x, g1y, g1z),
			g2: bls.NewG1Affine(g2x, g2y),
		}
	}
	b.ResetTimer()

	count := 0
	for i := 0; i < b.N; i++ {
		inData[count].g1.AddAffine(inData[count].g2)
		count = (count + 1) % g1MulAssignSamples
	}
}
