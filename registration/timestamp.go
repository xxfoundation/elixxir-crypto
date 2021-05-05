////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package registration

import (
	"encoding/binary"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"gitlab.com/xx_network/crypto/xx"
	"hash"
	"io"
	"time"
)

// This file handles signature and verification logic of the timestamp for a user's verification.
// This is used to verify that a user has registered with the network at a specific data and time

// SignTimestamp signs a hash of the timestamp and the user's public key
func SignTimestamp(rand io.Reader, priv *rsa.PrivateKey, ts time.Time,
	userPubKey *rsa.PublicKey) ([]byte, error) {
	// Construct the hash
	options := rsa.NewDefaultOptions()

	// Digest the timestamp and public key
	hashedData := digestTimestamp(options.Hash.New(), ts, userPubKey)

	// Sign the data
	return rsa.Sign(rand, priv, options.Hash, hashedData, options)
}

// VerifyTimestamp verifies the signature provided against serverPubKey and the
// digest of the timestamp ts and userPubKey
func VerifyTimestamp(sig []byte, serverPubKey *rsa.PublicKey,
	ts time.Time, userPubKey *rsa.PublicKey) error {
	// Construct the hash
	options := rsa.NewDefaultOptions()

	// Digest the timestamp and public key
	hashedData := digestTimestamp(options.Hash.New(), ts, userPubKey)

	// Verify the signature
	return rsa.Verify(serverPubKey, options.Hash, hashedData, sig, options)
}

// digestTimestamp is a helper function which digests the timestamp ts and
// rsa.PublicKey userPubKey given hash h
func digestTimestamp(h hash.Hash, ts time.Time, userPubKey *rsa.PublicKey) []byte {
	// Serialize the public key
	pubKeyBytes := xx.PublicKeyBytes(&(*userPubKey).PublicKey)

	// Serialize the timestamp
	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(ts.UnixNano()))

	// Hash the data and verify
	h.Write(tsBytes)
	h.Write(pubKeyBytes)

	return h.Sum(nil)
}
