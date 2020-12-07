///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package cyclic

import (
	"gitlab.com/xx_network/crypto/large"
	"testing"
)

//Tests that getting and interacting with the intbuffer is correct
func TestIntBuffer_Get(t *testing.T) {
	p := large.NewInt(1000000010101111111)
	g := large.NewInt(5)
	grp := NewGroup(p, g)

	buf := grp.NewIntBuffer(5, nil)

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
	grp := NewGroup(p, g)

	for i := 0; i < 1000; i++ {
		ib := grp.NewIntBuffer(uint32(i), nil)
		if ib.Len() != i {
			t.Errorf("IntBuffer.Len: returned incorrect len, Expected: %v, Received: %v", i, ib.Len())
		}
	}
}

//Tests that GetFingerprint returns the correct fingerprint
func TestIntBuffer_GetFingerprint(t *testing.T) {
	p1 := large.NewInt(1000000010101111111)
	g := large.NewInt(5)
	grp1 := NewGroup(p1, g)

	ib1 := grp1.NewIntBuffer(5, nil)

	if ib1.GetFingerprint() != grp1.GetFingerprint() {
		t.Errorf("IntBuffer.GetFingerprint: returned incorrect fingerprint,"+
			"Expected: %v, Received: %v", grp1.GetFingerprint(), ib1.fingerprint)
	}

	p2 := large.NewInt(1000000010101111011)
	grp2 := NewGroup(p2, g)

	ib2 := grp2.NewIntBuffer(5, nil)

	if ib2.GetFingerprint() != grp2.GetFingerprint() {
		t.Errorf("IntBuffer.GetFingerprint: returned incorrect fingerprint,"+
			"Expected: %v, Received: %v", grp2.GetFingerprint(), ib2.fingerprint)
	}

}

//Tests that getting a region in the intbuffer works correctly
func TestIntBuffer_GetRegion(t *testing.T) {
	p := large.NewInt(1000000010101111111)
	g := large.NewInt(5)
	grp := NewGroup(p, g)

	intBuffLen := uint32(20)

	buf := grp.NewIntBuffer(intBuffLen, nil)

	// Set all ints
	for i := uint32(0); i < intBuffLen; i++ {
		grp.SetUint64(buf.Get(i), uint64(i))
	}

	begin := uint32(3)
	end := uint32(17)

	//Get a region of the int buffer
	bufSub := buf.GetSubBuffer(begin, end)

	//check that the length is correct
	if bufSub.Len() != int(end-begin) {
		t.Errorf("IntBuffer.GetSubBuffer: Size of region of incorrect,"+
			"Expected: %v, Received: %v", end-begin, bufSub.Len())
	}

	for i := begin; i < end; i++ {
		//check that the copy is exact
		bufint := bufSub.Get(i - begin)
		if bufint.GetLargeInt().Int64() != int64(i) {
			t.Errorf("IntBuffer.GetSubBuffer: Region mapped incorrectly,"+
				"Expected: %v, Received: %v", i, bufint.GetLargeInt().Int64())
		}
		//check that when editing one, the other is edited
		grp.SetUint64(bufint, uint64(100-i))
		if buf.Get(i).GetLargeInt().Int64() != int64(100-i) {
			t.Errorf("IntBuffer.GetSubBuffer: Region not connected to originator,"+
				"Expected: %v, Received: %v", 100-i, buf.Get(i).GetLargeInt().Int64())
		}
	}
}

//Tests that deep copy of an int buffer copies correctly
func TestIntBuffer_DeepCopy(t *testing.T) {
	p := large.NewInt(1000000010101111111)
	g := large.NewInt(5)
	grp := NewGroup(p, g)

	intBuffLen := uint32(20)

	buf := grp.NewIntBuffer(intBuffLen, nil)

	// Set all ints
	for i := uint32(0); i < intBuffLen; i++ {
		grp.SetUint64(buf.Get(i), uint64(i))
	}

	//Get a deep copy of the int buffer
	bufCpy := buf.DeepCopy()

	if bufCpy.Len() != buf.Len() {
		t.Errorf("IntBuffer.DeepCopy: Size of region of incorrect,"+
			"Expected: %v, Received: %v", buf.Len(), bufCpy.Len())
	}

	for i := uint32(0); i < intBuffLen; i++ {
		//check that the copy is the same as the original
		bufint := bufCpy.Get(i)
		if bufint.GetLargeInt().Int64() != int64(i) {
			t.Errorf("IntBuffer.DeepCopy: Copy not equal to original at %v,"+
				"Expected: %v, Received: %v", i, i, bufint.GetLargeInt().Int64())
		}
		//check that editing one does not edit the other
		grp.SetUint64(bufint, uint64(100-i))
		if buf.Get(i).GetLargeInt().Int64() == int64(100-i) {
			t.Errorf("IntBuffer.DeepCopy: Region connected to originator,"+
				"Expected: %v, Received: %v", 100-i, buf.Get(i).GetLargeInt().Int64())
		}
	}
}

func TestIntBuffer_Contains(t *testing.T) {
	p := large.NewInt(1000000010101111111)
	g := large.NewInt(5)
	grp := NewGroup(p, g)

	b := grp.NewIntBuffer(15, nil)

	for i := 0; i < b.Len(); i++ {
		if !b.Contains(uint32(i)) {
			t.Errorf("IntBuffer.Contains: Does not contain index %v when it does", i)
		}
	}

	if b.Contains(uint32(b.Len())) {
		t.Errorf("IntBuffer.Contains: Contains index %v when it doesnt", b.Len())
	}

	if b.Contains(uint32(b.Len() + 1)) {
		t.Errorf("IntBuffer.Contains: Contains index %v when it doesnt", b.Len()+1)
	}
}

// Tests that Erase() removes all underlying data from the IntBuffer.
func TestIntBuffer_Erase(t *testing.T) {
	ib := grp.NewIntBuffer(uint32(20), nil)

	ib.Erase()

	if ib.values != nil {
		t.Errorf("Erase() did not properly delete the IntBuffer's "+
			"underlying value\n\treceived: %v\n\texpected: %v",
			ib.values, nil)
	}

	if ib.fingerprint != 0 {
		t.Errorf("Erase() did not properly delete the IntBuffer's "+
			"underlying fingerprint\n\treceived: %v\n\texpected: %v",
			ib.fingerprint, 0)
	}
}
