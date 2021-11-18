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

// crypt.go contains logic pertaining to encryption and decryption.

package fileTransfer

import (
	"github.com/pkg/errors"
	"gitlab.com/xx_network/crypto/csprng"
	"golang.org/x/crypto/salsa20"
)

// NonceSize is the size of the nonce in bytes.
const (
	NonceSize = 8
)

// Error messages
const (
	macMismatchErr = "reconstructed MAC from decrypting does not match MAC from sender"
)

// EncryptPart encrypts an individual file part using a nonce and part key. The
// part key is generated from the transfer key and the fingerprint number. A
// random nonce is generated as padding for the ciphertext and used as part of
// the encryption.
func EncryptPart(transferKey TransferKey, partBytes []byte, fpNum uint16,
	rng csprng.Source) (ciphertext, mac, nonce []byte,
	err error) {

	nonce, err = csprng.Generate(NonceSize, rng)
	if err != nil {
		return nil, nil, nil, err
	}

	// Generate the part key and redefine as array
	partKey := getPartKey(transferKey, fpNum)
	partKeyArray := [32]byte(partKey)

	// Create byte slice to store encrypted data
	ciphertextLen := len(partBytes)
	ciphertext = make([]byte, ciphertextLen)

	// Salsa20 encrypt file part bytes
	salsa20.XORKeyStream(ciphertext, partBytes, nonce, &partKeyArray)

	// Create file part MAC
	mac = createPartMAC(nonce, partBytes, partKey)

	// The nonce and ciphertext are returned separately
	return ciphertext, mac, nonce, nil
}

// DecryptPart decrypts an individual file part. The part key and nonce are used
// to decrypt the ciphertext.
func DecryptPart(transferKey TransferKey, ciphertext, nonce, mac []byte,
	fpNum uint16) (filePartBytes []byte, err error) {

	// Generate the part key and redefine as array
	partKey := getPartKey(transferKey, fpNum)
	partKeyArray := [32]byte(partKey)

	// Create byte slice to store decrypted data
	filePartBytes = make([]byte, len(ciphertext))

	// Salsa20 decrypt encrypted file part bytes
	salsa20.XORKeyStream(filePartBytes, ciphertext, nonce, &partKeyArray)

	// Return an error if the MAC cannot be validated
	if !verifyPartMAC(nonce, filePartBytes, mac, partKey) {
		return nil, errors.New(macMismatchErr)
	}

	// Return decrypted data
	return filePartBytes, nil
}
