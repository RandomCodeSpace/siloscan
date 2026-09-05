package p

func f(paths []string) {
	for _, p := range paths {
		func() {
			defer close(p)
		}()
	}
}
