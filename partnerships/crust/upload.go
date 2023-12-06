////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package crust

import (
	"crypto"
	"encoding/binary"
	"github.com/pkg/errors"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"hash"
	"io"
	"time"
)

const (
	uploadGracePeriod = 1 * time.Minute
)

// SignUpload returns a signature that proves that the user
// wants to upload a new file. The timestamp indicates the time
// the user wanted to upload the file. Use serializeTimestamp
// to serialize the timestamp.
func SignUpload(rand io.Reader, userPrivKey *rsa.PrivateKey,
	file []byte, timestamp time.Time) ([]byte, error) {
	fileHash, err := HashFile(file)
	if err != nil {
		return nil, errors.Errorf("Failed to hash file: %v", err)
	}

	opts := rsa.NewDefaultOptions()
	opts.Hash = crypto.SHA256
	hashed := makeUploadHash(fileHash, serializeTimestamp(timestamp),
		opts.Hash.New())

	return rsa.Sign(rand, userPrivKey, opts.Hash, hashed, opts)
}

// VerifyUpload verifies the user's upload signature. The signature
// should be from SignUpload. The timestamp provided must be +-1 minute
// from the current time passed in as "now".
func VerifyUpload(userPublicKey *rsa.PublicKey,
	now, timestamp time.Time,
	fileHash, signature []byte) error {

	// Check if timestamp is within the grace period
	startOfPeriod := now.Add(-uploadGracePeriod)
	endOfPeriod := now.Add(uploadGracePeriod)
	if now.After(endOfPeriod) || now.Before(startOfPeriod) {
		return errors.Errorf("Timestamp %s is not in between "+
			"the grace period (%s, %s)",
			timestamp, startOfPeriod.String(), endOfPeriod.String())
	}

	// Hash together timestamp and
	opts := rsa.NewDefaultOptions()
	opts.Hash = crypto.SHA256
	hashed := makeUploadHash(fileHash, serializeTimestamp(timestamp),
		opts.Hash.New())

	return rsa.Verify(userPublicKey, opts.Hash, hashed, signature, opts)
}

// serializeTimestamp is a helper function which will serialize a
// [time.Time] to a byte slice. This will grab use time.Time's
// UnixNano function and serialize it using [binary.BigEndian].
func serializeTimestamp(timestamp time.Time) []byte {
	tsUnix := timestamp.UnixNano()
	tsSerialize := make([]byte, 8)
	binary.BigEndian.PutUint64(tsSerialize, uint64(tsUnix))
	return tsSerialize
}

// makeUploadHash is a helper function which hashes together the
// timestamp and file hash. This hashed will be what is signed.
func makeUploadHash(fileHash []byte, ts []byte, h hash.Hash) []byte {
	h.Write(fileHash)
	h.Write(ts)
	return h.Sum(nil)
}
