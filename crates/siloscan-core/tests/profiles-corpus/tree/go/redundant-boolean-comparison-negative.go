package p

func f(ok bool, m map[string]bool) bool {
	if v, found := m["k"]; found {
		return v
	}
	return ok
}
