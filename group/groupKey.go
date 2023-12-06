////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

// The group key is defined as the hash of the group Membership digest, a
// 256-bit preimage, and a constant. It will be used to seed keys, MACs, and
// message fingerprints.

package group

import (
	"encoding/base64"
	"github.com/pkg/errors"
	"golang.org/x/crypto/blake2b"
	"io"
)

// Constant used in key generation.
const keyConstant = "GroupKeyConstant"

// Length of data, in bytes.
const (
	KeyLen         = 32 // Group key
	KeyPreimageLen = 32 // Key preimage
)

// Error messages.
const (
	readKeyPreimageErr    = "New Group Key: failed to read bytes into preimage: %+v"
	readLenKeyPreimageErr = "New Group Key Preimage: number of bytes read %d != %d expected"
)

// Key is the 256-bit group key.
type Key [KeyLen]byte

// KeyPreimage is the 256-bit group key preimage generated from a CRNG.
type KeyPreimage [KeyPreimageLen]byte

// NewKey generates a new key for a group. The key is a hash of the group
// Membership digest, a 256-bit preimage, and a constant. An error is returned
// if the preimage is not of the correct size.
func NewKey(preimage KeyPreimage, membership Membership) Key {
	// Hash the preimage, membership digest, and constant
	h, _ := blake2b.New256(nil)
	h.Write(preimage[:])
	h.Write(membership.Digest())
	h.Write([]byte(keyConstant))

	var key Key
	copy(key[:], h.Sum(nil))

	return key
}

// Bytes returns the Key as a byte slice.
func (k Key) Bytes() []byte {
	return k[:]
}

// String returns the Key as a base 64 encoded string. This functions satisfies
// the fmt.Stringer interface.
func (k Key) String() string {
	return base64.StdEncoding.EncodeToString(k.Bytes())
}

// NewKeyPreimage generates a 256-bit preimage from a CRNG that is used for
// group key generation. An error is returned if the RNG does not return the
// correct number of bytes.
func NewKeyPreimage(rng io.Reader) (KeyPreimage, error) {
	var preimage KeyPreimage

	n, err := rng.Read(preimage[:])
	if err != nil {
		return preimage, errors.Errorf(readKeyPreimageErr, err)
	} else if n != KeyPreimageLen {
		return preimage, errors.Errorf(readLenKeyPreimageErr, n, KeyPreimageLen)
	}

	return preimage, nil
}

// Bytes returns the KeyPreimage as a byte slice.
func (kp KeyPreimage) Bytes() []byte {
	return kp[:]
}

// String returns the KeyPreimage as a base 64 encoded string. This functions
// satisfies the fmt.Stringer interface.
func (kp KeyPreimage) String() string {
	return base64.StdEncoding.EncodeToString(kp.Bytes())
}
