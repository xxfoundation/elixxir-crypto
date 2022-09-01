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

// crypt.go contains logic pertaining to encryption and decryption.

package fileTransfer

import (
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/primitives/format"
	"golang.org/x/crypto/chacha20"
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
	fp format.Fingerprint) (ciphertext, mac []byte) {

	// Generate the part key and redefine as array
	partKey := getPartKey(transferKey, fpNum)

	// Create byte slice to store encrypted data
	ciphertextLen := len(partBytes)
	ciphertext = make([]byte, ciphertextLen)

	// ChaCha20 encrypt file part bytes
	cipher, err := chacha20.NewUnauthenticatedCipher(
		partKey[:], fp[:chacha20.NonceSizeX])
	if err != nil {
		jww.FATAL.Panic(err)
	}
	cipher.XORKeyStream(ciphertext, partBytes)

	// Create file part MAC
	mac = createPartMAC(fp[:], partBytes, partKey)

	// The nonce and ciphertext are returned separately
	return ciphertext, mac
}

// DecryptPart decrypts an individual file part. The part key and nonce are used
// to decrypt the ciphertext.
func DecryptPart(transferKey TransferKey, ciphertext, mac []byte,
	fpNum uint16, fp format.Fingerprint) (filePartBytes []byte, err error) {

	// Generate the part key and redefine as array
	partKey := getPartKey(transferKey, fpNum)

	// Create byte slice to store decrypted data
	filePartBytes = make([]byte, len(ciphertext))

	// ChaCha20 encrypt file part bytes
	cipher, err := chacha20.NewUnauthenticatedCipher(
		partKey[:], fp[:chacha20.NonceSizeX])
	if err != nil {
		jww.FATAL.Panic(err)
	}
	cipher.XORKeyStream(filePartBytes, ciphertext)

	// Return an error if the MAC cannot be validated
	if !verifyPartMAC(fp[:], filePartBytes, mac, partKey) {
		return nil, errors.New(macMismatchErr)
	}

	// Return decrypted data
	return filePartBytes, nil
}
