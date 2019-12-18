////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package coin

import (
	"math"
	"testing"
)

//Tests that IsSeed returns false on all headers except for seed
func TestIsSeed_False(t *testing.T) {
	tst := make([]byte, BaseFrameLen)
	for i := byte(0); i < byte(math.MaxUint8); i++ {
		if i != SeedType {
			tst[HeaderLoc] = i
			if IsSeed(tst) {
				t.Errorf("IsSeed: Returned true for input %x which is not a seed",
					i)
			}
		}
	}
}

//Tests that IsSeed returns true for a seed header
func TestIsSeed_True(t *testing.T) {
	tst := make([]byte, BaseFrameLen)
	tst[HeaderLoc] = SeedType
	if !IsSeed(tst) {
		t.Errorf("IsSeed: Returned false for unput %x which is a seed",
			SeedType)
	}
}

//Tests that IsCompound returns false on all headers except for seed
func TestIsCompound_False(t *testing.T) {
	tst := make([]byte, BaseFrameLen)
	for i := byte(0); i < byte(math.MaxUint8); i++ {
		if i != CompoundType {
			tst[HeaderLoc] = i
			if IsCompound(tst) {
				t.Errorf("IsCompound: Returned true for input %x which is not a compound",
					i)
			}
		}
	}
}

//Tests that IsSeed returns true for a seed header
func TestIsCompound_True(t *testing.T) {
	tst := make([]byte, BaseFrameLen)
	tst[HeaderLoc] = CompoundType
	if !IsCompound(tst) {
		t.Errorf("IsCompound: Returned false for unput %x which is a compound",
			CompoundType)
	}
}
