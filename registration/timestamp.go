////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package registration

import (
	"encoding/binary"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"hash"
	"io"
)

// This file handles signature and verification logic of the timestamp for a user's verification.
// This is used to verify that a user has registered with the network at a specific data and time

// SignWithTimestamp signs a hash of the timestamp and the user's public key
func SignWithTimestamp(rand io.Reader, priv *rsa.PrivateKey,
	timestampNano int64, userPubKeyPem string) ([]byte, error) {
	// Construct the hash
	options := rsa.NewDefaultOptions()

	// Digest the timestamp and public key
	hashedData := digest(options.Hash.New(), timestampNano, userPubKeyPem)

	// Sign the data
	return rsa.Sign(rand, priv, options.Hash, hashedData, options)
}

// VerifyWithTimestamp verifies the signature provided against serverPubKey and the
// digest of the timestamp ts and userPubKey
func VerifyWithTimestamp(serverPubKey *rsa.PublicKey,
	timestampNano int64, userPubKeyPem string, sig []byte) error {
	// Construct the hash
	options := rsa.NewDefaultOptions()

	// Digest the timestamp and public key
	hashedData := digest(options.Hash.New(), timestampNano, userPubKeyPem)

	// Verify the signature
	return rsa.Verify(serverPubKey, options.Hash, hashedData, sig, options)
}

// digest is a helper function which digests the timestamp ts and
// rsa.PublicKey userPubKey given hash h
func digest(h hash.Hash, timestampNano int64, userPubKeyPem string) []byte {

	// Serialize the timestamp
	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(timestampNano))

	// Hash the data and verify
	h.Write(tsBytes)
	h.Write([]byte(userPubKeyPem))

	return h.Sum(nil)
}
