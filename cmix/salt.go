////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// Package cmix derives new keys within the cyclic group from salts and a base key.
// It also is used for managing keys and salts for communication between clients
package cmix

import (
	jww "github.com/spf13/jwalterweatherman"
	"git.xx.network/xx_network/crypto/csprng"
)

// NewSalt creates a byte slice of `size` using the provided output from the
// given cryptographically secure pseudo-random number generator
func NewSalt(csprng csprng.Source, size int) []byte {
	b := make([]byte, size)
	size, err := csprng.Read(b)
	if err != nil || size != len(b) {
		jww.FATAL.Panicf("Could not generate salt: %v", err.Error())
	}
	return b
}
