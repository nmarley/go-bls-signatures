package main

import (
	"fmt"
	"math/big"
)

func main() {
	bigSeven := big.NewInt(7)
	bigTwo := big.NewInt(2)

	fmt.Println("seven bit zero : ", bigSeven.Bit(0))
	fmt.Println("two bit zero : ", bigTwo.Bit(0))
}
