////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package crust

import (
	"crypto/sha256"
	multiHash "github.com/multiformats/go-multihash/core"
)

const (
	usernameHashSalt = "CrustXXBackupUsernameSalt"
	multiHashSize    = 32
	multiHashSha     = multiHash.SHA2_256
)

// hashUsername hashes the passed in username using the sha256 hashing algorithm.
func hashUsername(username string) []byte {
	h := sha256.New()
	h.Write([]byte(username))
	h.Write([]byte(usernameHashSalt))

	return h.Sum(nil)
}

// hashFile hashes the file using the go-multihash library.
func hashFile(file []byte) ([]byte, error) {
	h, err := multiHash.GetVariableHasher(multiHashSha, multiHashSize)
	if err != nil {
		return nil, err
	}

	h.Write(file)
	return h.Sum(nil), nil
}
