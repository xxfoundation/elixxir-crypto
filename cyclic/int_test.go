////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package cyclic

import (
	"bytes"
	"gitlab.com/elixxir/crypto/large"
	"testing"
)

func TestGetLargeInt(t *testing.T) {
	p := large.NewInt(1000000010101111111)
	s := large.NewInt(192395897203)
	min := large.NewInt(2)
	max := large.NewInt(0)
	max.Mul(p, large.NewInt(1000))
	g := large.NewInt(5)
	rng := NewRandom(min, max)
	grp := NewGroup(p, s, g, rng)

	tests := 1

	pass := 0

	expected := large.NewInt(42)

	actual := grp.NewInt(42)

	if actual.GetLargeInt().Cmp(expected) != 0 {
		t.Errorf("Test of GetLargeInt failed, expected: '%v', got: '%v'",
			actual.GetLargeInt(), expected)
	} else {
		pass++
	}

	println("TestGetLargeInt()", pass, "out of", tests, "tests passed.")
}

func TestGetGroupFingerprint(t *testing.T) {
	p := large.NewInt(1000000010101111111)
	s := large.NewInt(192395897203)
	min := large.NewInt(2)
	max := large.NewInt(0)
	max.Mul(p, large.NewInt(1000))
	g := large.NewInt(5)
	rng := NewRandom(min, max)
	grp := NewGroup(p, s, g, rng)

	tests := 1

	pass := 0

	expected := grp.GetFingerprint()

	actual := grp.NewInt(int64(42))

	if actual.GetGroupFingerprint() != expected {
		t.Errorf("Test of GetGroupFingerprint failed, expected: '%v', got: '%v'",
			actual.GetGroupFingerprint(), expected)
	} else {
		pass++
	}

	println("TestGetGroupFingerprint()", pass, "out of", tests, "tests passed.")
}

func TestBytes(t *testing.T) {
	p := large.NewInt(1000000010101111111)
	s := large.NewInt(192395897203)
	min := large.NewInt(2)
	max := large.NewInt(0)
	max.Mul(p, large.NewInt(1000))
	g := large.NewInt(5)
	rng := NewRandom(min, max)
	grp := NewGroup(p, s, g, rng)

	tests := 1

	pass := 0

	expected := []byte{0x2A}

	actual := grp.NewInt(int64(42))

	if !bytes.Equal(actual.Bytes(), expected) {
		t.Errorf("Test of Bytes failed, expected: '%v', got: '%v'",
			actual.Bytes(), expected)
	} else {
		pass++
	}

	println("TestBytes()", pass, "out of", tests, "tests passed.")
}

func TestLeftpadBytes(t *testing.T) {
	p := large.NewInt(1000000010101111111)
	s := large.NewInt(192395897203)
	min := large.NewInt(2)
	max := large.NewInt(0)
	max.Mul(p, large.NewInt(1000))
	g := large.NewInt(5)
	rng := NewRandom(min, max)
	grp := NewGroup(p, s, g, rng)

	tests := 1

	pass := 0

	expected := []byte{0x00, 0x00, 0x00, 0x2A}

	actual := grp.NewInt(int64(42))

	if !bytes.Equal(actual.LeftpadBytes(4), expected) {
		t.Errorf("Test of LeftPadBytes failed, expected: '%v', got: '%v'",
			actual.LeftpadBytes(4), expected)
	} else {
		pass++
	}

	println("TestLeftPadBytes()", pass, "out of", tests, "tests passed.")
}
