///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package factID

import (
	"gitlab.com/elixxir/primitives/fact"
	"gitlab.com/xx_network/crypto/hasher"
)

// Creates a fingerprint of a fact
func Fingerprint(f fact.Fact) []byte {
	h := hasher.BLAKE2.New()
	h.Write([]byte(f.Fact))
	h.Write([]byte(f.T.Stringify()))
	return h.Sum(nil)
}
