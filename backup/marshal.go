///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package backup

import (
	"bytes"
	"encoding/json"
	"errors"

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
	if !bytes.Equal(acquiredTag, []byte(tag)) {
		return errors.New("tag mismatch")
	}
	acquiredVersion := int(b[tagSize])
	if acquiredVersion != version {
		return errors.New("version mismatch")
	}
	return nil
}

type TransmissionIdentity struct {
	RSASigningPrivateKey  *rsa.PrivateKey
	RegistrarSignature    []byte
	Salt                  []byte
	ComputedID            *id.ID
	RegistrationTimestamp int64
}

type ReceptionIdentity struct {
	RSASigningPrivateKey  *rsa.PrivateKey
	RegistrarSignature    []byte
	Salt                  []byte
	ComputedID            *id.ID
	DHPrivateKey          *cyclic.Int
	DHPublicKey           *cyclic.Int
	RegistrationTimestamp int64
}

type UserDiscoveryRegistration struct {
	Username *fact.Fact
	Email    *fact.Fact
	Phone    *fact.Fact
}

type Contacts struct {
	Identities []*id.ID
}

type Backup struct {
	TransmissionIdentity      TransmissionIdentity
	ReceptionIdentity         ReceptionIdentity
	UserDiscoveryRegistration UserDiscoveryRegistration
	Contacts                  Contacts
}

func (b *Backup) Unmarshal(key, blob []byte) error {

	if err := checkMarshalledTagVersion(blob); err != nil {
		return err
	}
	blob = blob[tagSize+versionSize:]

	plaintext, err := Decrypt(blob, key)
	if err != nil {
		return err
	}

	return json.Unmarshal(plaintext, b)
}

// Marshal returns the serialized backup with the format for account backups:
//   "XXACCTBAK" | [VERSION as 1 byte] | [DATA]
func (b Backup) Marshal(rand csprng.Source, key []byte) ([]byte, error) {

	blob, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}

	ciphertext, err := Encrypt(rand, blob, key)
	if err != nil {
		return nil, err
	}

	tagVersion := marshalTagVersion()
	return append(tagVersion, ciphertext...), nil
}
