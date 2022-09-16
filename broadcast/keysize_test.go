package broadcast

import (
	"gitlab.com/elixxir/crypto/rsa"
	"math/rand"
	"testing"
)

func Test_calculateKeySize(t *testing.T) {
	paylaodSize := 7416/8

	rng := rand.New(rand.NewSource(69))

	for i :=0;i<1000;i++{
		maxkeysize := int(rng.Uint64()%uint64(paylaodSize))
		key, n := calculateKeySize(paylaodSize, maxkeysize)

		//check that the packet is within bounds
		if key*(n+1)+rsa.ELength>MaxSizedBroadcastPayloadSize(paylaodSize){
			t.Errorf("returned keysize is too large")
		}

		//check that the returned keysize is not larger than the max
		if key>(MaxSizedBroadcastPayloadSize(paylaodSize)-rsa.ELength)/2{
			t.Errorf("returned keysize is too large")
		}
	}
}
