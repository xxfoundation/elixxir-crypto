package cmix

import (
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/large"

	"testing"
)

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func TestSelectGroupBit(t *testing.T) {
	c := csprng.Source(&csprng.SystemRNG{})

	p := large.NewIntFromString(pString, base)
	g := large.NewIntFromString(gString, base)
	grp := cyclic.NewGroup(p, g)
	primeLength := len(grp.GetPBytes())

	testCount := 10000
	trues := 0
	falses := 0
	for i := 0; i < testCount; i++ {

		payload := make([]byte, primeLength)
		_, err := c.Read(payload)
		if err != nil {
			t.Fatalf("RNG fail: %v", err)
		}

		ret := SelectGroupBit(payload, p.Bytes(), c)
		if ret {
			trues++
		} else {
			falses++
		}
	}

	t.Logf("True: %d False: %d", trues, falses)
	if abs(trues-falses) > 100 {
		t.Fatalf("Difference between trues/falses is greater than 100. True: %d False: %d", trues, falses)
	}
}
