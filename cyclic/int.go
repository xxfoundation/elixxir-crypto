////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package cyclic

import (
	"gitlab.com/elixxir/crypto/large"
)

// Create the cyclic.Int type as a wrapper of a large.Int
// and group fingerprint
type Int struct {
	value       large.Int
	fingerprint uint64
}

func (z *Int) GetLargeInt() large.Int {
	return z.value
}

func (z *Int) GetGroupFingerprint() uint64 {
	return z.fingerprint
}

func (z *Int) Bytes() []byte {
	return z.value.Bytes()
}

func (z *Int) LeftpadBytes(length uint64) []byte {
	return z.value.LeftpadBytes(length)
}
