package broadcast

import (
	"gitlab.com/elixxir/crypto/rsa"
	"math/rand"
	"testing"
)

func Test_calculateKeySize(t *testing.T) {
	payloadSize := 7416 / 8

	rng := rand.New(rand.NewSource(69))

	for i := 0; i < 1000; i++ {
		maxKeySize := int(rng.Uint64() % uint64(payloadSize))
		key, n := calculateKeySize(payloadSize, maxKeySize)

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
