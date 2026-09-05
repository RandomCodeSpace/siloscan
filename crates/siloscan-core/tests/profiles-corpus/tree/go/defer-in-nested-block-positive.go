package p

func f(paths []string, ok bool) {
	for _, p := range paths {
		if ok {
			defer close(p)
		}
	}
}
