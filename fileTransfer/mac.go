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

// mac.go contains logic pertaining to MAC generation and verification.

package fileTransfer

import (
	"crypto/hmac"

	"gitlab.com/elixxir/crypto/hash"
)

// CreateTransferMAC creates a MAC for the entire file. This is for consistency
// upon reconstruction of the file parts.
func CreateTransferMAC(fileData []byte, key TransferKey) []byte {
	return hash.CreateHMAC(fileData, key.Bytes())
}

// VerifyTransferMAC verifies that the transfer MAC matches the received file
// data. This is for consistency upon reconstruction
func VerifyTransferMAC(fileData []byte, key TransferKey, mac []byte) bool {
	generatedMac := CreateTransferMAC(fileData, key)
	return hmac.Equal(generatedMac, mac)
}

// createPartMAC creates the MAC for the given file part, its padding, and the
// part key.
func createPartMAC(nonce, partData []byte, partKey partKey) []byte {
	h := hmac.New(hash.DefaultHash, partKey.Bytes())
	h.Write(nonce)
	h.Write(partData)
	mac := h.Sum(nil)

	// Set the first bit to be 0 to comply with the group requirements in the
	// cMix message format.
	mac[0] &= 0x7F

	return mac
}

// verifyPartMAC verifies that the received MAC matches the given part MAC.
func verifyPartMAC(nonce, partData, partMac []byte, partKey partKey) bool {
	generatedMac := createPartMAC(nonce, partData, partKey)
	return hmac.Equal(generatedMac, partMac)
}
