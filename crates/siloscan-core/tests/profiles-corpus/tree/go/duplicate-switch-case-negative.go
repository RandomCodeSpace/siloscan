package p

func f(n int) int {
	switch n {
	case 1, 2:
		return 10
	case 3:
		return 20
	case 4:
		return 30
	}
	return 0
}
