package e2e

import (
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/elixxir/primitives/id"
	"golang.org/x/crypto/blake2b"
)

// derives a single key fingerprint at position keynum using blake2B on
// the concatenation of the second half of the cyclic basekey, the passed
// userID, and the keynum
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
