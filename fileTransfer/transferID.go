////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

// Package fileTransfer contains all cryptographic functions pertaining to the
// transfer of large (MB) files over the xx network. It is designed to use
// standard end-to-end encryption. However, it is separated from package e2e to
// ensure encryption keys are not shared between the two systems to avoiding key
// exhaustion.

// transferID.go contains logic pertaining to transferID generation

package fileTransfer

import (
	"encoding/base64"
	"encoding/json"
	"github.com/pkg/errors"
	"gitlab.com/xx_network/crypto/csprng"
)

// TransferIdLength is the length, in bytes, of the TransferKey.
const TransferIdLength = 32

// Error messages
const (
	// NewTransferID
	tidReadRandomErr = "failed to generate random bytes: %+v"

	// TransferID.UnmarshalJSON
	unmarshalTransferIdLenErr = "data must be %d bytes; received %d bytes"
)

// TransferID is a 256-bit randomly generated ID that is used to track the
// transfer progress of a file transfer.
type TransferID [TransferIdLength]byte

// NewTransferID generates a new TransferID. Returns an error if an error occurs
// when generating random bytes or if the number of generated bytes is
// insufficient.
func NewTransferID(rng csprng.Source) (TransferID, error) {
	data, err := csprng.Generate(TransferIdLength, rng)
	if err != nil {
		return TransferID{}, errors.Errorf(tidReadRandomErr, err)
	}

	return UnmarshalTransferID(data), err
}

// UnmarshalTransferID converts the byte slice to a TransferID.
func UnmarshalTransferID(b []byte) TransferID {
	var tid TransferID
	copy(tid[:], b[:])
	return tid
}

// Bytes returns the TransferID as a byte slice.
func (tid *TransferID) Bytes() []byte {
	return tid[:]
}

// String returns the TransferID as a base 64 encoded string. This functions
// satisfies the fmt.Stringer interface.
func (tid *TransferID) String() string {
	return base64.StdEncoding.EncodeToString(tid.Bytes())
}

// MarshalJSON is part of the [json.Marshaler] interface and allows TransferID
// objects to be marshaled into JSON.
func (tid *TransferID) MarshalJSON() ([]byte, error) {
	return json.Marshal(tid[:])
}

// UnmarshalJSON is part of the [json.Unmarshaler] interface and allows JSON to
// be unmarshalled into TransferID objects.
func (tid *TransferID) UnmarshalJSON(b []byte) error {
	var buff []byte
	if err := json.Unmarshal(b, &buff); err != nil {
		return err
	}

	if len(buff) != TransferIdLength {
		return errors.Errorf(
			unmarshalTransferIdLenErr, TransferIdLength, len(buff))
	}

	copy(tid[:], buff)

	return nil
}
