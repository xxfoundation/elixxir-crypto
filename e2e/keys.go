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

// Packagee 2e contains functions used in the end-to-end encryption algorithm, including
// the end-to-end key rotation.
package e2e

import (
	"fmt"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/primitives/format"
	"golang.org/x/crypto/blake2b"
)

const ReKeyStr = "REKEY"
const KeyLen = 32

type Key [KeyLen]byte

// derives a single key at position keynum using blake2B on the concatenation
// of the first half of the cyclic basekey and the keynum and the salts
// Key = H(First half of base key | keyNum | salt[0] | salt[1] | ...)
func DeriveKey(basekey *cyclic.Int, keyNum uint32, salts ...[]byte) Key {
	//use the first half of the bits to create the key
	data := basekey.Bytes()
	data = data[:len(data)/2]

	//get the hash
	h, err := blake2b.New256(nil)
	if err != nil {
		panic(fmt.Sprintf("Failed to create hash for "+
			"DeriveKey: %s", err))
	}

	//derive the key
	keyBytes := derive(h, data, keyNum, salts...)

	//put the keybytes in a key object and return
	k := Key{}
	copy(k[:], keyBytes)
	return k
}

// derives a single key fingerprint at position keynum using blake2B on
// the concatenation of the second half of the cyclic basekey and the keynum
// and the salts
// Fingerprint = H(Second half of base key | userID | keyNum | salt[0] | salt[1] | ...)
func DeriveKeyFingerprint(dhkey *cyclic.Int, keyNum uint32, salts ...[]byte) format.Fingerprint {
	//use the first half of the bits to create the key
	data := dhkey.Bytes()
	data = data[len(data)/2:]

	//get the hash
	h, err := blake2b.New256(nil)
	if err != nil {
		panic(fmt.Sprintf("Failed to create hash for "+
			"DeriveKeyFingerprint(): %s", err))
	}
	//derive the key
	fpBytes := derive(h, data, keyNum, salts...)

	//put the keybytes in a key object and return
	fp := format.Fingerprint{}
	copy(fp[:], fpBytes)

	// set the first bit of the fingerprint to 0 to ensure the final stored
	// payloads are within the group
	fp[0] &= 0x7f

	return fp
}
