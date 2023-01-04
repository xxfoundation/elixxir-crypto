////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package channel

import (
	"math/rand"
	"testing"

	"gitlab.com/elixxir/crypto/codename"
)

// Consistency test for decode version "0".
func Test_decodeVer0_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(42))

	var identities []PrivateIdentity

	for i := 0; i < 10; i++ {
		pi, err := codename.GenerateIdentity(prng)
		if err != nil {
			t.Fatalf("Failed to generate identity %d: %+v", i, err)
		}

		identities = append(identities, PrivateIdentity{pi})

		password := make([]byte, 16)
		prng.Read(password)

	}

}
