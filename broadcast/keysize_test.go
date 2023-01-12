package broadcast

import (
	"gitlab.com/elixxir/crypto/rsa"
	"testing"
)

func Test_calculateKeySize(t *testing.T) {
	payloadSize := 7416 / 8

	for i := 0; i < 3200; i += 32 {
		key, n := calculateKeySize(payloadSize + i)

		// check that the packet is within bounds
		if key*(n+1)+rsa.ELength > MaxSizedBroadcastPayloadSize(payloadSize+i) {
			t.Errorf("returned keysize is too large")
		}

		// check that the returned key size is not larger than the max
		if key > (MaxSizedBroadcastPayloadSize(payloadSize+i)-rsa.ELength)/2 {
			t.Errorf("returned keysize is too large")
		}

		//check that the returned key size is divisable by 128
		if key%128 != 0 {
			t.Errorf("returned keysize (%d) is not a factor of 128", key)
		}
	}
}

// Test_calculateKeySize_NetworkStandard verifies that the system gives the correct
func Test_calculateKeySize_NetworkStandard(t *testing.T) {
	payloadSize := 6016
	key, n := calculateKeySize(payloadSize)

	if n != 1 {
		t.Errorf("wrong n recieved from calculate payload size: %d, expected 1", n)
	}

	if key != 2944 {
		t.Errorf("wrong key size recieved from calculate payload size: %d, "+
			"expected 2944", key)
	}
}
