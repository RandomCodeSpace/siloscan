package p

import "strings"

func f(err, other error) bool {
	return err.Error() == other.Error() || strings.Contains(err.Error(), "not found")
}
