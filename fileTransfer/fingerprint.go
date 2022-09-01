////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

// Package fileTransfer contains all cryptographic functions pertaining to the
// transfer of large (MB) files over the xx network. It is designed to use
// standard end-to-end encryption. However, it is separated from package e2e to
// ensure encryption keys are not shared between the two systems to avoiding key
// exhaustion.

package fileTransfer

import (
	"encoding/binary"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/elixxir/primitives/format"
)

const fingerprintVector = "FileTransferKeyFingerprint"

// GenerateFingerprints generates the key fingerprints for all file parts.
func GenerateFingerprints(startKey TransferKey, numFingerprints uint16) []format.Fingerprint {
	fingerprints := make([]format.Fingerprint, numFingerprints)
	for i := uint16(0); i < numFingerprints; i++ {
		fingerprints[i] = GenerateFingerprint(startKey, i)
	}

	return fingerprints
}

// GenerateFingerprint generates an individual fingerprint for a file part given
// the fingerprint number.
func GenerateFingerprint(transferKey TransferKey, fpNum uint16) format.Fingerprint {
	h, _ := hash.NewCMixHash()
	h.Reset()

	// Convert file part number to bytes
	partNumBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(partNumBytes, fpNum)

	// Hash the transfer key, file part number, and the vector
	h.Write(transferKey.Bytes())
	h.Write(partNumBytes)
	h.Write([]byte(fingerprintVector))

	// Create new key fingerprint from hash
	fp := format.NewFingerprint(h.Sum(nil))

	// Set the first bit to be 0 to comply with the group requirements in the
	// cMix message format.
	fp[0] &= 0x7F

	return fp
}
