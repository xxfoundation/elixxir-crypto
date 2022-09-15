package broadcast

import (
	"testing"
)

func Test_calculateKeySize(t *testing.T) {
	paylaodSize := 7416/8

	maxkeysize := 1600/8

	key, n := calculateKeySize(paylaodSize, maxkeysize)

	if key*(n)>paylaodSize{
		t.Error("Key doesnt fit in payload")
	}
}
