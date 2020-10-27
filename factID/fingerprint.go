////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

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
