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

//Tests that getting and interacting with the intbuffer is correct
func TestIntBuffer_Get(t *testing.T) {
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

//Tests that len works correctly
func TestIntBuffer_Len(t *testing.T) {
	p := large.NewInt(1000000010101111111)
	g := large.NewInt(5)
	q := large.NewInt(1283)
	grp := NewGroup(p, g, q)

	for i := 0; i < 1000; i++ {
		ib := grp.NewIntBuffer(uint32(i))
		if ib.Len() != i {
			t.Errorf("IntBuffer.Len: returned incorrect len, Expected: %v, Recieved: %v", i, ib.Len())
		}
	}
}

//Tests that GetFingerprint returns the correct fingerprint
func TestIntBuffer_GetFingerprint(t *testing.T) {
	p1 := large.NewInt(1000000010101111111)
	g := large.NewInt(5)
	q := large.NewInt(1283)
	grp1 := NewGroup(p1, g, q)

	ib1 := grp1.NewIntBuffer(5)

	if ib1.GetFingerprint() != grp1.GetFingerprint() {
		t.Errorf("IntBuffer.GetFingerprint: returned incorrect fingerprint,"+
			"Expected: %v, Recieved: %v", grp1.GetFingerprint(), ib1.fingerprint)
	}

	p2 := large.NewInt(1000000010101111011)
	grp2 := NewGroup(p2, g, q)

	ib2 := grp2.NewIntBuffer(5)

	if ib2.GetFingerprint() != grp2.GetFingerprint() {
		t.Errorf("IntBuffer.GetFingerprint: returned incorrect fingerprint,"+
			"Expected: %v, Recieved: %v", grp2.GetFingerprint(), ib2.fingerprint)
	}

}

//Tests that getting a region in the intbuffer works correctly
func TestIntBuffer_GetRegion(t *testing.T) {
	p := large.NewInt(1000000010101111111)
	g := large.NewInt(5)
	q := large.NewInt(1283)
	grp := NewGroup(p, g, q)

	intBuffLen := uint32(20)

	buf := grp.NewIntBuffer(intBuffLen)

	// Set all ints
	for i := uint32(0); i < intBuffLen; i++ {
		grp.SetUint64(buf.Get(uint(i)), uint64(i))
	}

	//Get a region of the int buffer
	bufSub := buf.GetRegion(3, 17)

	for i := 3; i < 17; i++ {
		bufint := bufSub.Get(uint(i - 3))
		if bufint.GetLargeInt().Int64() != int64(i) {
			t.Errorf("IntBuffer.GetRegion: Region mapped incorrectly,"+
				"Expected: %v, Recieved: %v", i, bufint.GetLargeInt().Int64())
		}
		grp.SetUint64(bufint, uint64(100-i))
		if buf.Get(uint(i)).GetLargeInt().Int64() != int64(100-i) {
			t.Errorf("IntBuffer.GetRegion: Region not connect to originator,"+
				"Expected: %v, Recieved: %v", 100-i, buf.Get(uint(i)).GetLargeInt().Int64())
		}
	}
}
