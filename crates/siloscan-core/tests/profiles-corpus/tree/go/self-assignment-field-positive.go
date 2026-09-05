package p

type T struct{ a int }

func f(t *T) {
	t.a = t.a
}
