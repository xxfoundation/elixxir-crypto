////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package cyclic

import (
	"gitlab.com/elixxir/crypto/large"
	"testing"
)

func TestIntBuffer_Set(t *testing.T) {
	p := large.NewInt(1000000010101111111)
	g := large.NewInt(5)
	q := large.NewInt(1283)
	grp := NewGroup(p, g, q)

	buf := grp.NewIntBuffer(5)

	// Set an int
	grp.SetUint64(buf.Get(2), 322)

	// Ensure that overwriting a large int in the buffer doesn't overwrite any of
	// the things it shouldn't overwrite
	shouldStillBePSub1 := buf.Get(0)
	if shouldStillBePSub1.Cmp(grp.NewInt(1000000010101111110)) != 0 {
		t.Error("Setting the buffer element also set another element of the" +
			" buffer (probably aliased)")
	}
	shouldAlsoStillBePSub1 := grp.GetPSub1()
	if shouldAlsoStillBePSub1.value.Cmp(large.NewInt(1000000010101111110)) != 0 {
		t.Error("Setting the buffer element also set PSub1 (probably aliased)")
	}

	// Ensure that when you get an int that you've set,
	// it has the value that you set it to
	shouldBe322 := buf.Get(2)
	if shouldBe322.Cmp(grp.NewInt(322)) != 0 {
		t.Error("The buffer item that should have been set to 322 wasn't")
	}
}
