/* Copyright 2020 xx network SEZC

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.

*/

// Package cyclic wraps our large.Int structure.  It is designed to be used in
// conjunction with the cyclic.Group object. The cyclic.Group object
// will provide implementations of various modular operations within the group.
// A cyclic.IntBuffer type will be created to store large batches of groups.
package cyclic

import (
	"gitlab.com/xx_network/crypto/large"
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
