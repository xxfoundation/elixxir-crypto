package cmix

import (
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/large"

	"testing"
)

type fakeRNG struct {
	count int
}

func newFakeRNG() *fakeRNG {
	return &fakeRNG{
		count: 0,
	}
}

func (s *fakeRNG) Read(b []byte) (int, error) {
	if s.count > 255 {
		panic("wtf")
	}
	b[0] = byte(s.count)
	s.count++
	return 1, nil
}

func (s *fakeRNG) SetSeed(seed []byte) error {
	return nil
}

func TestSelectGroupBit_ByteMask(t *testing.T) {
	//c := csprng.Source(&csprng.SystemRNG{})
	c := newFakeRNG()

	// make a fake prime which is all 1s to ensure we never get
	// lower than the "prime"
	primeLength := 4096 / 8
	fakePrime := make([]byte, primeLength)
	for i := 0; i < primeLength; i++ {
		fakePrime[i] = 0b11111111
	}

	testCount := 256
	trues := 0
	falses := 0
	for i := 0; i < testCount; i++ {

		payload := make([]byte, primeLength)
		payload[primeLength-1] = 5

		ret := SelectGroupBit(payload, fakePrime, c)
		if ret {
			trues++
		} else {
			falses++
		}
	}

	if trues != 128 || falses != 128 {
		t.Fatal("fail")
	}
}

func TestSelectGroupBit_InGroup(t *testing.T) {
	prime := large.NewIntFromString(pString, base)
	payload := prime.Add(prime, prime)
	c := csprng.Source(&csprng.SystemRNG{})
	ret := SelectGroupBit(payload.Bytes(), prime.Bytes(), c)
	if ret {
		t.Fatal("fail, not in group")
	}

	payload = prime.Add(large.NewInt(int64(0)), large.NewInt(int64(1)))
	ret = SelectGroupBit(payload.Bytes(), prime.Bytes(), c)
	if ret {
		t.Fatal("fail, not in group")
	}
}

func abs(a int) int {
	if a < 0 {
		return -a
	}
	return a
}
