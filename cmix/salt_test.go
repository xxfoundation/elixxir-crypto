////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package cmix

import (
	"gitlab.com/elixxir/crypto/csprng"
	"testing"
)

func TestSaltSystemRand(t *testing.T) {
	c := csprng.Source(&csprng.SystemRNG{})
	salt := NewSalt(c, 16)
	if len(salt) != 16 {
		t.Errorf("Couldn't use systmeRNG, got %d bytes instead of 16",
			len(salt))
	}
}

func TestSaltPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Salt should panic on negative size!")
		}
	}()
	c := csprng.Source(&csprng.SystemRNG{})
	NewSalt(c, -1)
}
