package p

func f(c bool) int {
	if c {
		return 1
		// the branch above is the fast path
	}
	return 0
}
