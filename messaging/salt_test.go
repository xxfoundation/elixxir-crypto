////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package messaging

import (
	"gitlab.com/privategrity/crypto/csprng"
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
