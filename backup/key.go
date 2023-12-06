////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package backup

import (
	"github.com/pkg/errors"
	"gitlab.com/xx_network/crypto/csprng"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// KeyLen is the length of the backup key generated
	KeyLen = chacha20poly1305.KeySize

	// SaltLen is the required length of the salt. Recommended being set to 16
	// bytes here:
	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-argon2-04#section-3.1
	SaltLen = 16
)

// Error message
const errSaltLen = "length of generated salt %d must be %d"

// DeriveKey derives a key from a user supplied password and a salt via the
// Argon2 algorithm.
func DeriveKey(password string, salt []byte, params Params) []byte {
	return argon2.IDKey([]byte(password), salt, params.Time, params.Memory,
		params.Threads, KeyLen)
}

// MakeSalt generates a salt of the correct length of key generation.
func MakeSalt(csprng csprng.Source) ([]byte, error) {
	b := make([]byte, SaltLen)
	size, err := csprng.Read(b)
	if err != nil {
		return nil, err
	} else if size != SaltLen {
		return nil, errors.Errorf(errSaltLen, size, SaltLen)
	}

	return b, nil
}
