////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package e2e

import (
	"encoding/base64"
	"encoding/json"

	"github.com/pkg/errors"

	"gitlab.com/elixxir/crypto/hash"
)

// KeyResidue generation constants.
const (
	residueSalt      = `e2eKeyResidueSalt`
	KeyResidueLength = 32
)

// Error constants for KeyResidue.
const (
	keyResidueIncorrectLenErr = "binary key residue is the wrong length"
)

// KeyResidue is the residue of a Key. It represents a hash of the
// Key and a residue salt.
type KeyResidue [KeyResidueLength]byte

// NewKeyResidue returns a residue of a Key. The
// residue is the hash of the key with the residueSalt.
func NewKeyResidue(key Key) KeyResidue {
	h := hash.DefaultHash()
	h.Write(key[:])
	h.Write([]byte(residueSalt))
	kr := KeyResidue{}
	copy(kr[:], h.Sum(nil))
	return kr
}

// UnmarshalKeyResidue a KeyResidue from a byte slice binary format.
// Returns an error if the passed byte slice is the wrong length.
func UnmarshalKeyResidue(b []byte) (KeyResidue, error) {
	if len(b) != KeyResidueLength {
		return KeyResidue{}, errors.New(keyResidueIncorrectLenErr)
	}

	kr := KeyResidue{}
	copy(kr[:], b)
	return kr, nil
}

// Marshal returns the serialized KeyResidue into a binary format.
func (kr KeyResidue) Marshal() []byte {
	return kr[:]
}

// String adheres to the stringer interface to return a truncated
// base64 encoded string of the KeyResidue.
func (kr KeyResidue) String() string {
	return kr.StringVerbose()[:8] + "..."
}

// StringVerbose returns an un-truncated base64 encoding of the message iD.
func (kr KeyResidue) StringVerbose() string {
	s := base64.StdEncoding.EncodeToString(kr[:])
	return s
}

// MarshalJSON marshals the [KeyResidue] into valid JSON. This function adheres
// to the [json.Marshaler] interface.
func (kr KeyResidue) MarshalJSON() ([]byte, error) {
	return json.Marshal(kr.Marshal())
}

// UnmarshalJSON unmarshalls the JSON into the [KeyResidue]. This function
// adheres to the [json.Unmarshaler] interface.
func (kr *KeyResidue) UnmarshalJSON(data []byte) error {
	var krBytes []byte
	err := json.Unmarshal(data, &krBytes)
	if err != nil {
		return err
	}

	newKR, err := UnmarshalKeyResidue(krBytes)
	if err != nil {
		return err
	}

	*kr = newKR

	return nil
}
