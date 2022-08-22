////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package e2e

import "gitlab.com/elixxir/crypto/hash"

const (
	residueSalt = `e2eKeyResidueSalt`
)

// MakeKeyResidue returns a residue of a Key. The
// residue is the hash of the key with the residueSalt.
func MakeKeyResidue(key Key) []byte {
	h := hash.DefaultHash()
	h.Write(key[:])
	h.Write([]byte(residueSalt))
	h.Write(nil)
	return h.Sum(nil)
}
