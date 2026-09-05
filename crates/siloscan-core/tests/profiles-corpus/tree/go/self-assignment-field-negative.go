package p

type T struct{ a, b int }

func f(t *T) {
	t.a = t.b
}
