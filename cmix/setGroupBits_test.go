package cmix

import (
	"gitlab.com/xx_network/crypto/csprng"
	"testing"
)

func TestSelectGroupBit_ByteMask(t *testing.T) {
	c := csprng.Source(&csprng.SystemRNG{})

	// make a fake prime which is all 1s to ensure we never get
	// lower than the "prime"
	primeLength := 4096/8
	fakePrime := make([]byte,primeLength)
	for i:=0;i<primeLength;i++{
		fakePrime[i] = 0b11111111
	}

	// calculate teh acceptable error rate.
	// given we are splitting an 8 bit number, the error could
	// be up to 1/2^8 = 1/256. given that these are proabilities,
	// we can assume that anything beyond half that can be an issuse.
	// meaning the total error should not be more than 1/512
	// of the number of samples
	acceptableError := float64(1)/float64(512)

	testCount := 1000000
	trues := 0
	falses := 0
	for i := 0; i < testCount; i++ {

		payload := make([]byte, primeLength)
		payload[primeLength-1]=5

		ret := SelectGroupBit(payload, fakePrime, c)
		if ret {
			trues++
		} else {
			falses++
		}
	}

	errorRatio := float64(abs(trues-falses))/float64(testCount)
	if errorRatio > acceptableError {
		t.Fatalf("Difference between trues/falses is greater than %f. True: " +
			"%d False: %d, runs: %d, ratio:%f", acceptableError, trues, falses, testCount, errorRatio)
	}
}

func abs(a int)int{
	if a<0{
		return -a
	}
	return a
}
