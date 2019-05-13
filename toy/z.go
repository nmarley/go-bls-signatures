package main

import (
	"fmt"
)

func main() {
	n := []byte{7}
	buf := [2]byte{}
	copy(buf[:], n) // <-- BUG!! This results in an array like [2]byte{0x7, 0x0}
	fmt.Println("buf =", buf)
	// buf = [7 0]

	// Reset buffer
	buf = [2]byte{}

	copy(buf[2-len(n):], n) // <-- What we really want is this
	fmt.Println("buf =", buf)
	// buf = [0 7]
}
