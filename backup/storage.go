///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package backup

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"

	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/primitives/fact"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"gitlab.com/xx_network/primitives/id"
)

const (
	tag     = 12345
	tagSize = 2

	version     = 0
	versionSize = 1
)

func MarshalTagVersion() []byte {
	out := make([]byte, tagSize+versionSize)
	binary.BigEndian.PutUint16(out[:2], tag)
	out[2] = byte(version)
	return out
}

func CheckMarshalledTagVersion(b []byte) error {
	acquiredTag := binary.BigEndian.Uint16(b[:2])
	if acquiredTag != tag {
		return errors.New("tag mismatch")
	}
	acquiredVersion := int(b[2])
	if acquiredVersion != version {
		return errors.New("version mismatch")
	}
	return nil
}

type TransmissionIdentity struct {
	RSASigningPrivateKey *rsa.PrivateKey
	RegistrarSignature   []byte
	Salt                 []byte
	ComputedID           []byte
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

func (b *Backup) Load(filepath string, key []byte) error {

	blob, err := ioutil.ReadFile(filepath)
	if err != nil {
		return err
	}

	if err = CheckMarshalledTagVersion(blob); err != nil {
		return err
	}
	blob = blob[3:]

	plaintext, err := Decrypt(blob, key)
	if err != nil {
		return err
	}

	return json.Unmarshal(plaintext, b)
}

func (b *Backup) Store(rand csprng.Source, filepath string, key []byte) error {

	blob, err := json.Marshal(b)
	if err != nil {
		return err
	}

	ciphertext, err := Encrypt(rand, blob, key)
	if err != nil {
		return err
	}

	tagVersion := MarshalTagVersion()
	ciphertext = append(tagVersion, ciphertext...)

	tmpfile, err := ioutil.TempFile("", "state")
	if err != nil {
		return err
	}

	tmpPath := tmpfile.Name()

	_, err = tmpfile.Write(ciphertext)
	if err != nil {
		return err
	}

	err = tmpfile.Close()
	if err != nil {
		return err
	}

	err = os.Rename(tmpPath, filepath)
	return err
}
