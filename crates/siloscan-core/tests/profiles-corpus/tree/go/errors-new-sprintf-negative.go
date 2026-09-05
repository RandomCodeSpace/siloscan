package p

import "fmt"

func f(n int) error {
	return fmt.Errorf("bad %d", n)
}
