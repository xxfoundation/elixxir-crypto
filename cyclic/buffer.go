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
func (ib *IntBuffer) Get(index uint32) *Int {
	return &Int{&ib.values[index], ib.fingerprint}
}

//Get an intBuffer representing a specific region in the int buffer
func (ib *IntBuffer) GetSubBuffer(begin, end uint32) *IntBuffer {
	return &IntBuffer{
		values:      ib.values[begin:end],
		fingerprint: ib.fingerprint}
}

//Get a deep copy of an intBuffer
func (ib *IntBuffer) DeepCopy() *IntBuffer {
	newBuffer := IntBuffer{make([]large.Int, len(ib.values)), ib.fingerprint}
	for i := range newBuffer.values {
		(&newBuffer.values[i]).Set(&ib.values[i])
	}
	return &newBuffer
}

//Gets the length of the int buffer
func (ib *IntBuffer) Len() int {
	return len(ib.values)
}

//Gets the int buffer's group fingerprint
func (ib *IntBuffer) GetFingerprint() uint64 {
	return ib.fingerprint
}

func (ib *IntBuffer) Contains(index uint32) bool {
	return index < uint32(len(ib.values))
}

// Erase removes all underlying data from an IntBuffer by overwriting the values
// with ones and setting the fingerprint to zero.
func (ib *IntBuffer) Erase() {
	// Loop through each value in the slice and clear its value
	for i := range ib.values {
		// Get number of bytes in the cyclic Int's value
		length := (ib.values[i].BitLen() + 7) / 8

		// Make a new byte slice of the same length and fill it with ones
		clearedBytes := make([]byte, length)
		for j := range clearedBytes {
			clearedBytes[j] = 0xFF
		}

		// Overwrite value with the cleared bytes
		ib.values[i].SetBytes(clearedBytes)
	}

	// Set the fingerprint to zero, overwriting any present data
	ib.fingerprint = 0
}
