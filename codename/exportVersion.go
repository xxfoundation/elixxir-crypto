////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package codename

import (
	"bytes"
	"encoding/base64"

	"github.com/pkg/errors"
	"gitlab.com/elixxir/crypto/backup"
)

// This file contains the different decoding functions for each version of the
// PrivateIdentity export structure.

// Error messages.
const (
	// decodeVer0
	base64DecodeErr    = "could not base 64 decode string: %+v"
	unmarshalParamsErr = "could not unmarshal params: %+v"
)

// decodeVer0 decodes the PrivateIdentity encoded data. This function is for
// version "1" of the structure, defined below.
//
//	+---------------------+----------------------------------------------+
//	| Encryption Metadata |                Encrypted Data                |
//	+----------+----------+---------+---------+-------------+------------+
//	|   Salt   |  Argon   | Version | Codeset |   ed25519   |  ed25519   |
//	|          |  params  |         | Version | Private Key | Public Key |
//	| 16 bytes | 9 bytes  | 1 byte  | 1 byte  |   64 bytes  |  32 bytes  |
//	+----------+----------+---------+---------+-------------+------------+
//	|                          base 64 encoded                           |
//	+--------------------------------------------------------------------+
func decodeVer0(password string, data []byte) (PrivateIdentity, error) {
	// Create a new buffer from a base64 decoder so that the data can be read
	// and decoded at the same time.
	decoder := base64.NewDecoder(base64.StdEncoding, bytes.NewReader(data))
	var buff bytes.Buffer
	_, err := buff.ReadFrom(decoder)
	if err != nil {
		return PrivateIdentity{}, errors.Errorf(base64DecodeErr, err)
	}

	// Get salt
	salt := buff.Next(saltLen)

	// Get and unmarshal Argon2 parameters
	var params backup.Params
	err = params.Unmarshal(buff.Next(backup.ParamsLen))
	if err != nil {
		return PrivateIdentity{}, errors.Errorf(unmarshalParamsErr, err)
	}

	// Derive decryption key and decrypt the data
	key := deriveKey(password, salt, params)
	decryptedData, err := decryptIdentity(buff.Bytes(), key)
	if err != nil {
		return PrivateIdentity{}, errors.Errorf(decryptionErr, err)
	}

	pi, err := decodePrivateIdentity(decryptedData)
	if err != nil {
		return PrivateIdentity{}, errors.Errorf(decodeErr, err)
	}

	return pi, nil
}
