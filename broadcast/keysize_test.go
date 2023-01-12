package broadcast

import (
	"gitlab.com/elixxir/crypto/rsa"
	"testing"
)

func Test_calculateKeySize(t *testing.T) {
	payloadSize := 7416 / 8

	for i := 0; i < 1000; i++ {
		key, n := calculateKeySize(payloadSize)

		// check that the packet is within bounds
		if key*(n+1)+rsa.ELength > MaxSizedBroadcastPayloadSize(payloadSize) {
			t.Errorf("returned keysize is too large")
		}

		// check that the returned key size is not larger than the max
		if key > (MaxSizedBroadcastPayloadSize(payloadSize)-rsa.ELength)/2 {
			t.Errorf("returned keysize is too large")
		}
	}
}
