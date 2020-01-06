////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
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

// Get gets the cyclic int at a specific index in the int buffer
func (ib *IntBuffer) Get(index uint32) *Int {
	return &Int{&ib.values[index], ib.fingerprint}
}

// GetSubBuffer get an intBuffer representing a specific region in the int buffer
func (ib *IntBuffer) GetSubBuffer(begin, end uint32) *IntBuffer {
	return &IntBuffer{
		values:      ib.values[begin:end],
		fingerprint: ib.fingerprint}
}

// DeepCopy gets a deep copy of an intBuffer
func (ib *IntBuffer) DeepCopy() *IntBuffer {
	newBuffer := IntBuffer{make([]large.Int, len(ib.values)), ib.fingerprint}
	for i := range newBuffer.values {
		(&newBuffer.values[i]).Set(&ib.values[i])
	}
	return &newBuffer
}

// Len gets the length of the int buffer
func (ib *IntBuffer) Len() int {
	return len(ib.values)
}

// GetFingerprint gets the int buffer's group fingerprint
func (ib *IntBuffer) GetFingerprint() uint64 {
	return ib.fingerprint
}

// Contains checks that the index is within the amount of the values slice
func (ib *IntBuffer) Contains(index uint32) bool {
	return index < uint32(len(ib.values))
}

// Erase overwrites all underlying data from an IntBuffer by setting its values
// slice to nil and its fingerprint to zero. All underlying released data will
// be removed by the garbage collector.
func (ib *IntBuffer) Erase() {
	ib.values = nil
	ib.fingerprint = 0
}
