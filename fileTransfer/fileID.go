////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package fileTransfer

import (
	"encoding/base64"
	"encoding/json"

	"github.com/pkg/errors"
	"gitlab.com/elixxir/crypto/hash"
)

const IdLen = 32

// ID identifies each unique file. It is a perceptual hash of a file so that all
// files that are the same and extremely similar share the same ID.
type ID [IdLen]byte

// NewID generates a new ID by taking a hash of the file.
func NewID(fileData []byte) ID {
	h, _ := hash.NewCMixHash()

	h.Write(fileData)

	var id ID
	copy(id[:], h.Sum(nil))

	return id
}

// Marshal returns the file ID as a byte slice.
func (id ID) Marshal() []byte {
	return id[:]
}

// UnmarshalID converts the byte slice to a file ID.
func UnmarshalID(b []byte) ID {
	var id ID
	copy(id[:], b[:])
	return id
}

// String returns the file ID as a base 64 encoded string. This function adheres
// to the fmt.Stringer interface.
func (id ID) String() string {
	return base64.StdEncoding.EncodeToString(id.Marshal())
}

// MarshalJSON adheres to the [json.Marshaler] interface.
func (id ID) MarshalJSON() ([]byte, error) {
	return json.Marshal(id.Marshal())
}

// UnmarshalJSON adheres to the [json.Unmarshaler] interface.
func (id *ID) UnmarshalJSON(b []byte) error {
	var buff []byte
	if err := json.Unmarshal(b, &buff); err != nil {
		return err
	}

	if len(buff) != IdLen {
		return errors.Errorf(
			"read %d bytes; %d bytes required", len(buff), IdLen)
	}

	copy(id[:], buff)

	return nil
}
