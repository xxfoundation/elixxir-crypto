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
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/elixxir/primitives/id"
	"golang.org/x/crypto/blake2b"
)

const ReKeyStr = "REKEY"
const KeyLen = 32

type Key [KeyLen]byte

// derives a single key at position keynum using blake2B on the concatenation
// of the first half of the cyclic basekey, the passed userID, and the keynum
// Key = H(First half of base key | userID | keyNum)
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
// ReKey = H(First half of base key | userID | ReKeyStr | keyNum)
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

// derives a single key fingerprint at position keynum using blake2B on
// the concatenation of the second half of the cyclic basekey, the passed
// userID, and the keynum
// Fingerprint = H(Second half of base key | userID | keyNum)
func DeriveKeyFingerprint(dhkey *cyclic.Int, userID *id.ID, keyNum uint32) (format.Fingerprint, error) {
	//use the first half of the bits to create the key
	data := dhkey.Bytes()
	data = data[len(data)/2:]
	//add the userID to ensure uniqueness
	data = append(data, userID.Bytes()...)

	//get the hash
	h, err := blake2b.New256(nil)
	if err != nil {
		return format.Fingerprint{}, err
	}
	//derive the key
	fpBytes := derive(h, data, keyNum)

	//put the keybytes in a key object and return
	fp := format.Fingerprint{}
	copy(fp[:], fpBytes)
	return fp, nil
}

// derives a single key fingerprint for rekeying at position keynum using
// blake2B on the concatenation of the first half of the cyclic basekey,
// the passed userID, the designated rekey string, and the keynum
// Fingerprint = H(Second half of base key | userID | ReKeyStr | keyNum)
func DeriveReKeyFingerprint(dhkey *cyclic.Int, userID *id.ID, keyNum uint32) (format.Fingerprint, error) {
	//use the first half of the bits to create the key
	data := dhkey.Bytes()
	data = data[len(data)/2:]
	//add the userID to ensure uniqueness
	data = append(data, userID.Bytes()...)
	//add the rekey bytes to it
	data = append(data, []byte(ReKeyStr)...)

	//get the hash
	h, err := blake2b.New256(nil)
	if err != nil {
		return format.Fingerprint{}, err
	}
	//derive the key
	fpBytes := derive(h, data, keyNum)

	//put the keybytes in a key object and return
	fp := format.Fingerprint{}
	copy(fp[:], fpBytes)
	return fp, nil
}

/*Unused for now
// derives all key fingerprints up to position numKeys using blake2B on the
// concatenation of the first half of the cyclic basekey, the passed userID,
// and the keynum
func DeriveKeyFingerprints(dhkey *cyclic.Int, userID *id.ID, numKeys uint32) ([]format.Fingerprint, error) {
	//use the first half of the bits to create the key
	data := dhkey.Bytes()
	data = data[len(data)/2:]
	//add the userID to ensure uniqueness
	data = append(data, userID.Bytes()...)

	//get the hash
	h, err := blake2b.New256(nil)
	if err != nil {
		return []format.Fingerprint{}, err
	}

	//generate all fingerprints
	fpList := make([]format.Fingerprint, numKeys)
	for keyNum := uint32(0); keyNum < numKeys; keyNum++ {
		h.Reset()
		//derive the fingerprint
		fpBytes := derive(h, data, keyNum)
		//add tje fingerprint to the list
		fp := format.Fingerprint{}
		copy(fp[:], fpBytes)
		fpList[keyNum] = fp
	}

	return fpList, nil
}

// derives all key rekey fingerprints up to position numKeys using blake2B on
// the concatenation of the first half of the cyclic basekey, the passed userID,
// the designated rekey string, and the keynum
func DeriveReKeyFingerprints(dhkey *cyclic.Int, userID *id.ID, numKeys uint32) ([]format.Fingerprint, error) {
	//use the first half of the bits to create the key
	data := dhkey.Bytes()
	data = data[len(data)/2:]
	//add the userID to ensure uniqueness
	data = append(data, userID.Bytes()...)
	//add the rekey bytes to it
	data = append(data, []byte(ReKeyStr)...)

	//get the hash
	h, err := blake2b.New256(nil)
	if err != nil {
		return []format.Fingerprint{}, err
	}

	//generate all fingerprints
	fpList := make([]format.Fingerprint, numKeys)
	for keyNum := uint32(0); keyNum < numKeys; keyNum++ {
		h.Reset()
		//derive the fingerprint
		fpBytes := derive(h, data, keyNum)
		//add tje fingerprint to the list
		fp := format.Fingerprint{}
		copy(fp[:], fpBytes)
		fpList[keyNum] = fp
	}

	return fpList, nil
}*/
