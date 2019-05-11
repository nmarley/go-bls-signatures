package bls




// GetValidYCoordsForX solves y = sqrt(x^3 + ax + b) for both valid ys
func GetValidYCoordsForX(x *FQ) []*FQ {
	x3b := x.Square().Mul(x).Add(NewFQ(BCoeff))
	y := x3b.Sqrt()

	return []*FQ{y, y.Neg()}
}

func FuckYou() {

}
