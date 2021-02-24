////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package factID

import (
	"encoding/base64"
	"gitlab.com/elixxir/primitives/fact"
	"gitlab.com/xx_network/crypto/hasher"
)

// Salt used for fact hashing to prevent rainbow table attacks
// This string is a base64 encoding of a randomly generated 32 byte slice
var saltStr = "1DK2BBdsOb/2ml2uf5ARYK4a0Sj05+1zdXWjc50qQd8="

// Creates a fingerprint of a fact
func Fingerprint(f fact.Fact) []byte {
	h := hasher.BLAKE2.New()
	h.Write([]byte(f.Fact))
	h.Write([]byte(f.T.Stringify()))
	// Decode the base64 salt string. Error is suppressed due decoding a
	// hard-coded string
	salt, _ := base64.StdEncoding.DecodeString(saltStr)
	h.Write(salt)
	return h.Sum(nil)
}
