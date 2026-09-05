package p

import "testing"

func TestX(t *testing.T) {
	go func() {
		t.Error("boom")
	}()
}
