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
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/primitives/format"
	"golang.org/x/crypto/blake2b"
)

const ReKeyStr = "REKEY"
const KeyLen = 32

type Key [KeyLen]byte

// derives a single key at position keynum using blake2B on the concatenation
// of the first half of the cyclic basekey and the keynum
// Key = H(First half of base key | keyNum)
func DeriveKey(basekey *cyclic.Int, keyNum uint32) Key {
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
	keyBytes := derive(h, data, keyNum)

	//put the keybytes in a key object and return
	k := Key{}
	copy(k[:], keyBytes)
	return k
}

// derives a single key for rekeying at position keynum using blake2B on
// the concatenation of the first half of the cyclic basekey, the designated
// rekey string, and the keynum
// ReKey = H(First half of base key | ReKeyStr | keyNum)
func DeriveReKey(dhkey *cyclic.Int, keyNum uint32) Key {
	//use the first half of the bits to create the key
	data := dhkey.Bytes()
	data = data[:len(data)/2]

	//add the rekey bytes to it
	data = append(data, []byte(ReKeyStr)...)

	//get the hash
	h, err := blake2b.New256(nil)
	if err != nil {
		panic(fmt.Sprintf("Failed to create hash for "+
			"DeriveReKey: %s", err))
	}
	//derive the key
	keyBytes := derive(h, data, keyNum)

	//put the keybytes in a key object and return
	k := Key{}
	copy(k[:], keyBytes)
	return k
}

// derives a single key fingerprint at position keynum using blake2B on
// the concatenation of the second half of the cyclic basekey and the keynum
// Fingerprint = H(Second half of base key | userID | keyNum)
func DeriveKeyFingerprint(dhkey *cyclic.Int, keyNum uint32) format.Fingerprint {
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
	fpBytes := derive(h, data, keyNum)

	//put the keybytes in a key object and return
	fp := format.Fingerprint{}
	copy(fp[:], fpBytes)
	return fp
}

// derives a single key fingerprint for rekeying at position keynum using
// blake2B on the concatenation of the first half of the cyclic basekey
// the designated rekey string, and the keynum
// Fingerprint = H(Second half of base key | ReKeyStr | keyNum)
func DeriveReKeyFingerprint(dhkey *cyclic.Int, keyNum uint32) format.Fingerprint {
	//use the first half of the bits to create the key
	data := dhkey.Bytes()
	data = data[len(data)/2:]

	//add the rekey bytes to it
	data = append(data, []byte(ReKeyStr)...)

	//get the hash
	h, err := blake2b.New256(nil)
	if err != nil {
		panic(fmt.Sprintf("Failed to create hash for "+
			"DeriveReKeyFingerprint(): %s", err))
	}
	//derive the key
	fpBytes := derive(h, data, keyNum)

	//put the keybytes in a key object and return
	fp := format.Fingerprint{}
	copy(fp[:], fpBytes)
	return fp
}
