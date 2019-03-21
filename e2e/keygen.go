////////////////////////////////////////////////////////////////////////////////
// Copyright © 2019 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package e2e

import (
	"gitlab.com/elixxir/crypto/cyclic"
	jww "github.com/spf13/jwalterweatherman"
)

// Keygen takes a salt and the base key and generates a new key
// to be used for E2E encryption/decryption
// Right now the function simply returns 1
// TODO: Implement the proper keygen once defined
func Keygen(g *cyclic.Group, salt, basekey *cyclic.Int) *cyclic.Int {
	jww.WARN.Printf("End to End Encryption is not fully implemented, Keygen is not secure")
	return g.NewInt(1)
}