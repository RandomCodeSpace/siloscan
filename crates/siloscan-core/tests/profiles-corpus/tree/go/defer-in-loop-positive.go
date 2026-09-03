package p

func f(paths []string) {
	for _, p := range paths {
		defer close(p)
	}
}
