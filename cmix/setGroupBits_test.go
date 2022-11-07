////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package cmix

import (
	"bytes"
	"gitlab.com/elixxir/primitives/format"
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

//tests that the byte mask value resulst sin 50% 1s and 50% 0s
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

type all1RNG struct {
}

func newAll1RNG() *all1RNG {
	return &all1RNG{}
}

func (s *all1RNG) Read(b []byte) (int, error) {
	for i := 0; i < len(b); i++ {
		b[i] = 0b11111111
	}

	return len(b), nil
}

func (s *all1RNG) SetSeed(seed []byte) error {
	return nil
}

//tests that when the payload is outside the group with a leading 1, it makes the leading value a 0
func TestSelectGroupBit_InGroup(t *testing.T) {
	prime := large.NewIntFromString(pString, base)
	payload := prime.Add(prime, prime)
	// use an RNG that always returns 1 to ensure that in the event that
	// the in group test fails, the return will always be 1
	c := &all1RNG{}
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

func TestSetGroupBits(t *testing.T) {

	firstZero := false
	firstOne := false
	secondZero := false
	secondOne := false

	rnd := csprng.NewSystemRNG()

	prime := grp.GetP()
	for i := 0; i < 1000; i++ {

		msg := format.NewMessage(prime.ByteLen())

		payloadA := make([]byte, prime.ByteLen())
		rnd.Read(payloadA)
		payloadB := make([]byte, prime.ByteLen())
		rnd.Read(payloadB)

		msg.SetPayloadA(payloadA)
		msg.SetPayloadB(payloadB)

		msg2 := format.NewMessage(prime.ByteLen())
		msg2.SetPayloadA(payloadA)
		msg2.SetPayloadB(payloadB)

		SetGroupBits(msg, grp, rnd)

		if !bytes.Equal(msg.GetPayloadA(), msg2.GetPayloadA()) {
			first := msg.GetPayloadA()[0] >> 7
			if first == 0 {
				firstZero = true
			} else if first == 1 {
				firstOne = true
			} else {
				panic("wtf")
			}
		}

		if !bytes.Equal(msg.GetPayloadB(), msg2.GetPayloadB()) {
			second := msg.GetPayloadB()[0] >> 7
			if second == 0 {
				secondZero = true
			} else if second == 1 {
				secondOne = true
			} else {
				panic("wtf")
			}
		}

	} // end of for loop

	bools := []bool{firstZero, firstOne, secondZero, secondOne}
	for _, b := range bools {
		if !b {
			t.Fatal("fail")
		}
	}
}
