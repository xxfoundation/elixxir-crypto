////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package backup

import (
	"bytes"
	"crypto/hmac"
	"encoding/json"

	"github.com/pkg/errors"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/primitives/fact"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"gitlab.com/xx_network/primitives/id"
)

const (
	tag     = "XXACCTBK"
	tagSize = 8

	version     = 0
	versionSize = 1
)

func marshalTagVersion() []byte {
	out := make([]byte, tagSize+versionSize)
	copy(out[:tagSize], tag)
	out[tagSize] = byte(version)
	return out
}

func checkMarshalledTagVersion(b []byte) error {
	acquiredTag := b[:tagSize]
	if !hmac.Equal(acquiredTag, []byte(tag)) {
		return errors.New("tag mismatch")
	}
	acquiredVersion := int(b[tagSize])
	if acquiredVersion != version {
		return errors.New("version mismatch")
	}
	return nil
}

// marshalSaltParams marshals the salt and Params object into a byte slice.
func marshalSaltParams(salt []byte, params Params) []byte {
	buff := bytes.NewBuffer(nil)
	buff.Grow(SaltLen + ParamsLen)

	// Write salt to buffer
	buff.Write(salt)

	// Write marshalled params to buffer
	buff.Write(params.Marshal())

	return buff.Bytes()
}

// unmarshalSaltParams decodes the byte slice into a salt and Params.
func unmarshalSaltParams(data []byte) ([]byte, Params, error) {
	buff := bytes.NewBuffer(data)

	// Get salt from buffer
	salt := make([]byte, SaltLen)
	n, err := buff.Read(salt)
	if err != nil || n != SaltLen {
		return nil, Params{}, errors.Errorf("read salt failed: %+v", err)
	}

	// Unmarshal params from remaining bytes
	var params Params
	err = params.Unmarshal(buff.Bytes())
	if err != nil {
		return nil, Params{}, err
	}

	return salt, params, nil
}

type TransmissionIdentity struct {
	RSASigningPrivateKey *rsa.PrivateKey
	RegistrarSignature   []byte
	Salt                 []byte
	ComputedID           *id.ID
}

type ReceptionIdentity struct {
	RSASigningPrivateKey *rsa.PrivateKey
	RegistrarSignature   []byte
	Salt                 []byte
	ComputedID           *id.ID
	DHPrivateKey         *cyclic.Int
	DHPublicKey          *cyclic.Int
}

type UserDiscoveryRegistration struct {
	fact.FactList
}

type Contacts struct {
	Identities []*id.ID
}

type Backup struct {
	RegistrationTimestamp     int64
	RegistrationCode          string
	JSONParams                string
	TransmissionIdentity      TransmissionIdentity
	ReceptionIdentity         ReceptionIdentity
	UserDiscoveryRegistration UserDiscoveryRegistration
	Contacts                  Contacts
}

// Decrypt decrypts the encrypted serialized backup. Returns an error for
// invalid version or invalid tag.
func (b *Backup) Decrypt(password string, blob []byte) error {

	if err := checkMarshalledTagVersion(blob); err != nil {
		return err
	}

	saltParams := blob[tagSize+versionSize : tagSize+versionSize+SaltLen+ParamsLen]
	salt, params, err := unmarshalSaltParams(saltParams)
	if err != nil {
		return err
	}

	key := DeriveKey(password, salt, params)

	blob = blob[tagSize+versionSize+SaltLen+ParamsLen:]

	plaintext, err := Decrypt(blob, key)
	if err != nil {
		return err
	}

	return json.Unmarshal(plaintext, b)
}

// Encrypt returns the encrypted serialized backup with the format for account
// backups:
//
//	"XXACCTBAK" | [VERSION as 1 byte] | [salt and params] | [DATA]
//
// The key passed in must be derived via DeriveKey and the salt must be the same
// used to derive the key. Key derivation happens outside the encryption because
// it is slow, so that the key can be stored and reused.
func (b *Backup) Encrypt(rand csprng.Source, key, salt []byte, params Params) (
	[]byte, error) {

	blob, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}

	ciphertext, err := Encrypt(rand, blob, key)
	if err != nil {
		return nil, err
	}

	saltParams := marshalSaltParams(salt, params)
	tagVersionSaltParams := append(marshalTagVersion(), saltParams...)
	return append(tagVersionSaltParams, ciphertext...), nil
}
