////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package cyclic

import (
	"gitlab.com/elixxir/crypto/large"
)

// Store the same group fingerprint for multiple values
type IntBuffer struct {
	values      []large.Int
	fingerprint uint64
}

func (i *IntBuffer) Get(index int) *Int {
	return &Int{&i.values[index], i.fingerprint}
}
