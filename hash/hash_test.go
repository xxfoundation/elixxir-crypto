package hash

import (
	"testing"
)

// TestNewCMixHash tests that we get the expected value for the cmix hash
func TestNewCMixHash(t *testing.T) {
	expected := []byte{
		72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100, 33, 14, 87, 81,
		192, 38, 229, 67, 178, 232, 171, 46, 176, 96, 153, 218, 161, 209, 229,
		223, 71, 119, 143, 119, 135, 250, 171, 69, 205, 241, 47, 227, 168 }
	h, err := NewCMixHash()
	if err != nil {
		t.Errorf("NewCMixHash failed: %v", err)
	}

	actual := h.Sum([]byte("Hello, World!"))

	for i, b := range actual {
		if b != expected[i] {
			t.Errorf("NewCMixHash byte %v failed, expected: '%v', got: '%v'",
				i, expected, actual)
		}
	}
}
