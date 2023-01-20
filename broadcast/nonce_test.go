////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package broadcast

import (
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/xx_network/crypto/csprng"
	"testing"
)

// Tests that multiple calls to newNonce results in unique values.
// Note: test assumed the randomness sources used by newNonce is suitably
// random.
func Test_newNonce_Unique(t *testing.T) {
	c := csprng.NewSystemRNG()
	nonces := make(map[format.Fingerprint]bool, 50)

	for i := 0; i < 50; i++ {
		nonce := newNonce(c)

		if nonces[nonce] {
			t.Errorf("Nonce %s already exists in map.", nonce)
		} else {
			nonces[nonce] = true
		}
	}
}
