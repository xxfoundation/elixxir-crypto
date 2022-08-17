////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

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

// SignUpload returns a signature that proves that the user
// wants to upload a new file. The timestamp indicates the time
// the user wanted to upload the file. Use SerializeTimestamp
// to serialize the timestamp.
func SignUpload(rand io.Reader, userPrivKey *rsa.PrivateKey,
	file, timestamp []byte) ([]byte, error) {
	fileHash, err := hashFile(file)
	if err != nil {
		return nil, errors.Errorf("Failed to hash file: %v", err)
	}

	opts := rsa.NewDefaultOptions()
	opts.Hash = crypto.SHA256
	hashed := makeUploadHash(fileHash, timestamp,
		opts.Hash.New())

	return rsa.Sign(rand, userPrivKey, opts.Hash, hashed, opts)
}

// VerifyUpload verifies the user's upload signature. The signature
// should be from SignUpload.
func VerifyUpload(userPublicKey *rsa.PublicKey,
	file, timestamp, signature []byte) error {
	// Hash file
	fileHash, err := hashFile(file)
	if err != nil {
		return errors.Errorf("Failed to hash file: %v", err)
	}

	// Hash together timestamp and
	opts := rsa.NewDefaultOptions()
	opts.Hash = crypto.SHA256
	hashed := makeUploadHash(fileHash, timestamp,
		opts.Hash.New())

	return rsa.Verify(userPublicKey, opts.Hash, hashed, signature, opts)
}

// todo: docstring
func SerializeTimestamp(timestamp time.Time) []byte {
	tsUnix := timestamp.UnixNano()
	tsSerialize := make([]byte, 8)
	binary.BigEndian.PutUint64(tsSerialize, uint64(tsUnix))
	return tsSerialize
}

// todo: docstring
func makeUploadHash(fileHash []byte, ts []byte, h hash.Hash) []byte {
	h.Write(fileHash)
	h.Write(ts)
	return h.Sum(nil)
}
