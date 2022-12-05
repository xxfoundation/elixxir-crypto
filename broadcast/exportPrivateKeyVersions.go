////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package broadcast

import (
	"bytes"
	"encoding/base64"
	"github.com/pkg/errors"
	"gitlab.com/elixxir/crypto/backup"
)

// This file contains the different decoding functions for each version of the
// channel private key export structure.

// Error messages.
const (
	// decodeVer0
	base64DecodeErr    = "could not base 64 decode string: %+v"
	unmarshalParamsErr = "could not unmarshal params: %+v"
)

// decodeVer0 decodes the portablePrivKey encoded data. This function is for
// version "1" of the structure, defined below.
//
//	+----------------+---------------------+------------------------------+--------+
//	|     Header     | Encryption Metadata |        Encrypted Data        | Footer |
//	+------+---------+----------+----------+---------+----------+---------+--------+
//	| Open |         |   Salt   |  Argon   | Version | Channel  | Private | Close  |
//	| Tag  | Version |          |  params  |         |    ID    | Key PEM |  Tag   |
//	|      |         | 16 bytes | 9 bytes  |  1 byte | 33 bytes |   var   |        |
//	+------+---------+----------+----------+---------+----------+---------+--------+
//	|     string     |                   base 64 encoded                  | string |
//	+----------------+----------------------------------------------------+--------+
func decodeVer0(password string, data []byte) (*portablePrivKey, error) {
	// Create a new buffer from a base64 decoder so that the data can be read
	// and decoded at the same time.
	decoder := base64.NewDecoder(base64.StdEncoding, bytes.NewReader(data))
	var buff bytes.Buffer
	_, err := buff.ReadFrom(decoder)
	if err != nil {
		return nil, errors.Errorf(base64DecodeErr, err)
	}

	// Get salt
	salt := buff.Next(privKeyPasswordSaltLen)

	// Get and unmarshal Argon2 parameters
	var params backup.Params
	err = params.Unmarshal(buff.Next(backup.ParamsLen))
	if err != nil {
		return nil, errors.Errorf(unmarshalParamsErr, err)
	}

	// Derive decryption key and decrypt the data
	key := deriveKey(password, salt, params)
	decryptedData, err := decryptPrivateKey(buff.Bytes(), key)
	if err != nil {
		return nil, errors.Errorf(decryptionErr, err)
	}

	var ppk portablePrivKey
	err = ppk.decode(decryptedData)
	if err != nil {
		return nil, errors.Errorf(decodeErr, err)
	}

	return &ppk, nil
}
