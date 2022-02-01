///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package backup

import (
	"encoding/json"
	"io/ioutil"
	"os"

	"gitlab.com/xx_network/primitives/id"
)

type TransmissionIdentity struct {
	RSASigningPrivateKey []byte
	RegistrarSignature   []byte
	Salt                 []byte
	ComputedID           []byte
}

type ReceptionIdentity struct {
	RSASigningPrivateKey []byte
	RegistrarSignature   []byte
	Salt                 []byte
	ComputedID           []byte
	DHPrivateKey         []byte
	DHPublicKey          []byte
}

type UserDiscoveryRegistration struct {
	Username string
	Email    string
	Phone    string
}

type Contacts struct {
	Identities []id.ID
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

	plaintext, err := Decrypt(blob, key)
	if err != nil {
		return err
	}

	return json.Unmarshal(plaintext, b)
}

func (b *Backup) Store(filepath string, key []byte) error {

	blob, err := json.Marshal(b)
	if err != nil {
		return err
	}

	ciphertext, err := Encrypt(blob, key)
	if err != nil {
		return err
	}

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
