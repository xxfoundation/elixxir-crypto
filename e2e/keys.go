////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// Packagee 2e contains functions used in the end-to-end encryption algorithm, including
// the end-to-end key rotation.
package e2e

import (
	"fmt"
	"git.xx.network/elixxir/crypto/cyclic"
	"git.xx.network/elixxir/primitives/format"
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
