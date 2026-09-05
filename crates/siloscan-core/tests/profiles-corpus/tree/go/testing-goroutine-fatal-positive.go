package p

import "testing"

func TestX(t *testing.T, bad bool) {
	go func() {
		if bad {
			t.Fatal("boom")
		}
	}()
}
