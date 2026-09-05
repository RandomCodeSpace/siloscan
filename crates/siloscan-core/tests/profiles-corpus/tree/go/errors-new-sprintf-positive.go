package p

import (
	"errors"
	"fmt"
)

func f(n int) error {
	return errors.New(fmt.Sprintf("bad %d", n))
}
