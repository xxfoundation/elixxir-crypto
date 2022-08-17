////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// Package crust will contain cryptographic functions needed for communication between
// the xx messenger and Crust.
package crust

import (
	"crypto/sha256"
	multiHash "github.com/multiformats/go-multihash/core"
)

const (
	UsernameHashSalt = "CrustXXBackupUsernameSalt"
	multiHashSize    = 32
)

// todo: docstring
func HashUsername(username string) []byte {
	h := sha256.New()
	h.Write([]byte(username))
	h.Write([]byte(UsernameHashSalt))

	return h.Sum(nil)
}

// todo: docstring
func HashFile(file []byte) ([]byte, error) {
	h, err := multiHash.GetVariableHasher(multiHash.SHA2_256, multiHashSize)
	if err != nil {
		return nil, err
	}

	h.Write(file)
	return h.Sum(nil), nil
}
