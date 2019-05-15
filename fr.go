package bls

import (
	"crypto/rand"
	"io"
	"math/big"
)

// RFieldModulus is the modulus of the field.
// Order of G1, G2, and GT. r = (x4 - x2 + 1)
var RFieldModulus, _ = new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)

// FR is a big integer representing a finite field element mod RFieldModulus
type FR struct {
	n *big.Int
}

// NewFR creates a new field element.
func NewFR(n *big.Int) *FR {
	return &FR{
		n: new(big.Int).Mod(n, RFieldModulus),
	}
}

func (f FR) String() string {
	return f.n.String()
}

// ToBig converts the FR element to the underlying big number.
func (f *FR) ToBig() *big.Int {
	return new(big.Int).Set(f.n)
}

// RandFR generates a random FR element.
func RandFR(reader io.Reader) (*FR, error) {
	r, err := rand.Int(reader, RFieldModulus)
	if err != nil {
		return nil, err
	}
	return NewFR(r), nil
}
