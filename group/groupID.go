////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// The group ID identifies the group to each member.It is defined as the hash of
// the group Membership Digest, a preimage, and a constant. The group ID is of
// type id.ID with the type id.Group.

package group

import (
	"encoding/base64"
	"github.com/pkg/errors"
	"git.xx.network/xx_network/primitives/id"
	"golang.org/x/crypto/blake2b"
	"io"
)

// Constant used in ID generation.
const idConstant = "GroupIDConstant"

// IdPreimageLen is the length, in bytes, of the ID preimage.
const IdPreimageLen = 32

// Error messages.
const (
	readIdPreimageErr    = "New Group ID: failed to read bytes into preimage: %+v"
	readLenIDPreimageErr = "New Group ID Preimage: number of bytes read %d != %d expected"
)

// IdPreimage is the 256-bit group ID preimage generated from a CRNG.
type IdPreimage [IdPreimageLen]byte

// NewID generates a new id.ID of type id.Group. The ID is a hash of the group
// Membership digest, a 256-bit preimage, and a constant.
func NewID(preimage IdPreimage, membership Membership) *id.ID {
	// Hash the preimage, membership digest, and constant
	h, _ := blake2b.New256(nil)
	h.Write(preimage[:])
	h.Write(membership.Digest())
	h.Write([]byte(idConstant))

	// Create an ID from the hash and set the type to Group
	var groupID id.ID
	copy(groupID[:], h.Sum(nil))
	groupID.SetType(id.Group)

	return &groupID
}

// NewIdPreimage generates a 256-bit preimage from a CRNG that is used for group
// ID generation. An error is returned if the RNG does not return the correct
// number of bytes.
func NewIdPreimage(rng io.Reader) (IdPreimage, error) {
	var preimage IdPreimage
	n, err := rng.Read(preimage[:])
	if err != nil {
		return preimage, errors.Errorf(readIdPreimageErr, err)
	} else if n != IdPreimageLen {
		return preimage, errors.Errorf(readLenIDPreimageErr, n, IdPreimageLen)
	}

	return preimage, nil
}

// Bytes returns the IdPreimage as a byte slice.
func (idp IdPreimage) Bytes() []byte {
	return idp[:]
}

// String returns the IdPreimage as a base 64 encoded string. This functions
// satisfies the fmt.Stringer interface.
func (idp IdPreimage) String() string {
	return base64.StdEncoding.EncodeToString(idp.Bytes())
}
