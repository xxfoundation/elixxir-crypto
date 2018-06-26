////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package messaging

import (
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/privategrity/crypto/csprng"
)

// NewSalt creates a byteslize of `size` using the provided output from the
// given cryptographically secure pseudo-random number generator
func NewSalt(csprng *csprng.Source, size int) []byte {
	salt, err := csprng.Read(size)
	if err != nil {
		jww.FATAL.Panicf("Could not generate salt: %v", err.Error())
	}
	return salt
}
