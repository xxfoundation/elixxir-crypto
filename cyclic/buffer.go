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

//Get the cyclic int at a specific index in the int buffer
func (ib *IntBuffer) Get(index uint) *Int {
	return &Int{&ib.values[index], ib.fingerprint}
}

//Get an intBuffer representing a specific region in the int buffer
func (ib *IntBuffer) GetRegion(begin, end uint) *IntBuffer {
	return &IntBuffer{
		values:      ib.values[begin:end],
		fingerprint: ib.fingerprint}
}

//Gets the length of the int buffer
func (ib *IntBuffer) Len() int {
	return len(ib.values)
}

//Gets the int buffer's group fingerprint
func (ib *IntBuffer) GetFingerprint() uint64 {
	return ib.fingerprint
}
