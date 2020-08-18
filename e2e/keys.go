////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// Packagee 2e contains functions used in the end-to-end encryption algorithm, including
// the end-to-end key rotation.
package e2e

import (
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/primitives/id"
	"golang.org/x/crypto/blake2b"
)

const ReKeyStr = "REKEY"
const KeyLen = 32

type Key [KeyLen]byte

// derives a single key at position keynum using blake2B on the concatenation
// of the first half of the cyclic basekey, the passed userID, and the keynum
func DeriveKey(basekey *cyclic.Int, userID *id.ID, keyNum uint32) (Key, error) {
	//use the first half of the bits to create the key
	data := basekey.Bytes()
	data = data[:len(data)/2]
	//add the userID to ensure uniqueness
	data = append(data, userID.Bytes()...)

	//get the hash
	h, err := blake2b.New256(nil)
	if err != nil {
		return Key{}, err
	}

	//derive the key
	keyBytes := derive(h, data, keyNum)

	//put the keybytes in a key object and return
	k := Key{}
	copy(k[:], keyBytes)
	return k, nil
}

// derives a single key for rekeying at position keynum using blake2B on
// the concatenation of the first half of the cyclic basekey, the passed userID,
// the designated rekey string, and the keynum
func DeriveReKey(dhkey *cyclic.Int, userID *id.ID, keyNum uint32) (Key, error) {
	//use the first half of the bits to create the key
	data := dhkey.Bytes()
	data = data[:len(data)/2]
	//add the userID to ensure uniqueness
	data = append(data, userID.Bytes()...)
	//add the rekey bytes to it
	data = append(data, []byte(ReKeyStr)...)

	//get the hash
	h, err := blake2b.New256(nil)
	if err != nil {
		return Key{}, err
	}
	//derive the key
	keyBytes := derive(h, data, keyNum)

	//put the keybytes in a key object and return
	k := Key{}
	copy(k[:], keyBytes)
	return k, nil
}
