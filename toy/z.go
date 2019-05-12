package main

import (
	"fmt"
)

func main() {
	var seven uint = 7
	var eight uint = 8

	fmt.Println("seven =", seven & 0x7f)
	fmt.Println("eight =", eight)
}
