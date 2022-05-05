////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// Package fileTransfer contains all cryptographic functions pertaining to the
// transfer of large (MB) files over the xx network. It is designed to use
// standard end-to-end encryption. However, it is separated from package e2e to
// ensure encryption keys are not shared between the two systems to avoiding key
// exhaustion.

// keygen.go contains logic pertaining to key generation.

package fileTransfer

import (
	"encoding/base64"
	"encoding/binary"
	"github.com/pkg/errors"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/xx_network/crypto/csprng"
)

// Key length constants, in bytes.
const (
	componentKeyVector = "FileTransferComponentKey"
	partKeyLen         = 32
	TransferKeyLength  = 32
)

// Error messages.
const (
	trReadRandomErr = "failed to generate random bytes: %+v"
)

// TransferKey is the 256-bit key used to generate the MAC for a file transfer.
type TransferKey [TransferKeyLength]byte

// partKey is the 256-bit key used to encrypt/decrypt a file segment.
type partKey [partKeyLen]byte

// NewTransferKey creates a new TransferKey to be used for encryption when
// transferring a file to another user. Returns an error if an error occurs when
// generating random bytes or if the number of generated bytes is insufficient.
func NewTransferKey(rng csprng.Source) (TransferKey, error) {
	data, err := csprng.Generate(TransferKeyLength, rng)
	if err != nil {
		return TransferKey{}, errors.Errorf(trReadRandomErr, err)
	}

	return UnmarshalTransferKey(data), nil
}

// getPartKey generates the message based off of the TransferKey and the
// fingerprint number.
func getPartKey(tr TransferKey, fpNum uint16) partKey {
	h, _ := hash.NewCMixHash()
	h.Reset()

	// Convert the file part number to bytes
	partNumBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(partNumBytes, fpNum)

	// Write the TransferKey, part number, and componentKeyVector to the hash
	h.Write(tr.Bytes())
	h.Write(partNumBytes)
	h.Write([]byte(componentKeyVector))

	// Get hashed data
	keyData := h.Sum(nil)

	// Return hashed data as a partKey
	return unmarshalPartKey(keyData)
}

// UnmarshalTransferKey converts the byte slice to a TransferKey.
func UnmarshalTransferKey(b []byte) TransferKey {
	var key TransferKey
	copy(key[:], b[:])
	return key
}

// Bytes returns the TransferKey as a byte slice.
func (tr TransferKey) Bytes() []byte {
	return tr[:]
}

// String returns the TransferKey as a base 64 encoded string. This functions
// satisfies the fmt.Stringer interface.
func (tr TransferKey) String() string {
	return base64.StdEncoding.EncodeToString(tr.Bytes())
}

// unmarshalPartKey converts the byte slice to a partKey.
func unmarshalPartKey(b []byte) partKey {
	var pk partKey
	copy(pk[:], b[:])
	return pk
}

// Bytes returns the partKey as a byte slice.
func (pk partKey) Bytes() []byte {
	return pk[:]
}

// String returns the partKey as a base 64 encoded string. This functions
// satisfies the fmt.Stringer interface.
func (pk partKey) String() string {
	return base64.StdEncoding.EncodeToString(pk.Bytes())
}