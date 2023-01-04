////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package channel

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"strings"

	"github.com/pkg/errors"
	"gitlab.com/elixxir/crypto/backup"
	"gitlab.com/elixxir/crypto/codename"
	"golang.org/x/crypto/chacha20poly1305"
)

// Error messages.
const (
	// PrivateIdentity.export
	encryptErr = "could not encrypt PrivateIdentity: %+v"

	// ImportPrivateIdentity
	noDataErr         = "len of data is 0"
	noHeadFootTagsErr = "invalid format: %+v"
	noVersionTagErr   = "version tags not found: %+v"
	noVersionErr      = "version not found"
	noEncryptedData   = "no encrypted data found"
	wrongVersionErr   = "version must be %s or lower; received version %q"

	// decryptPrivateIdentity
	decryptionErr = "could not decrypt identity data: %+v"
	decodeErr     = "could not decode decrypted identity data: %+v"

	// getTagContents
	noOpenTagErr  = "missing opening tag"
	noCloseTagErr = "missing closing tag"
	swappedTagErr = "tags in wrong order"

	// decodePrivateIdentity
	unmarshalDataLenErr = "data must be %d bytes, length of data received is %d bytes"
	versionMismatchErr  = "version received %d is not compatible with current version %d"
)

// Tags indicate the start and end of data. The tags must only contain printable
// ASCII characters.
const (
	headTag     = "<xxChannelIdentity" // Start of the encoded data
	footTag     = "xxChannelIdentity>" // End of the encoded data
	openVerTag  = "("                  // Start of the encoding version number
	closeVerTag = ")"                  // End of the encoding version number
)

// Data lengths.
const (
	versionLen = 1
	codesetLen = 1

	// Length of the encoded output of PrivateIdentity.encode
	encodedLen = versionLen + codesetLen + ed25519.PrivateKeySize + ed25519.PublicKeySize

	// Length of the data part of the exported string returned by
	// PrivateIdentity.encode
	exportedLen = saltLen + backup.ParamsLen + encodedLen

	// keyLen is the length of the key used for encryption
	keyLen = chacha20poly1305.KeySize

	// saltLen is the length of the salt used in key generation. The recommended
	// size is 16 bytes, mentioned here:
	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-argon2-04#section-3.1
	saltLen = 16
)

// The current version of the encoded format returned by PrivateIdentity.encode.
const currentEncryptedVersion = uint8(0)

// Current version of the string returned by PrivateIdentity.Export.
const currentExportedVersion = "0"

// Map of exported encoding version numbers to their decoding functions.
var decodeVersions = map[string]func(
	password string, data []byte) (PrivateIdentity, error){
	currentExportedVersion: decodeVer0,
}

// Export exports the PrivateIdentity into a portable encrypted string that can
// be used to restore it later.
func (i PrivateIdentity) Export(password string, csprng io.Reader) ([]byte, error) {
	return i.export(password, backup.DefaultParams(), csprng)
}

// export encrypts and marshals the PrivateIdentity into a portable string.
//
//	+----------------+---------------------+----------------------------------------------+--------+
//	|     Header     | Encryption Metadata |                Encrypted Data                | Footer |
//	+------+---------+----------+----------+---------+---------+-------------+------------+--------+
//	| Open |         |   Salt   |  Argon   | Version | Codeset |   ed25519   |  ed25519   | Close  |
//	| Tag  | Version |          |  params  |         | Version | Private Key | Public Key |  Tag   |
//	|      |         | 16 bytes | 9 bytes  | 1 byte  | 1 byte  |   64 bytes  |  32 bytes  |        |
//	+------+---------+----------+----------+---------+---------+-------------+------------+--------+
//	|     string     |                          base 64 encoded                           | string |
//	+----------------+--------------------------------------------------------------------+--------+
func (i PrivateIdentity) export(password string, params backup.Params,
	csprng io.Reader) ([]byte, error) {

	// Encrypt the PrivateIdentity with the user password
	encryptedData, salt, err := i.encrypt(password, params, csprng)
	if err != nil {
		return nil, errors.Errorf(encryptErr, err)
	}

	// Add encryption metadata and encrypted data to buffer
	buff := bytes.NewBuffer(nil)
	buff.Grow(exportedLen)
	buff.Write(salt)
	buff.Write(params.Marshal())
	buff.Write(encryptedData)

	// Add header tag, version number, and footer tag
	encodedData := bytes.NewBuffer(nil)
	encodedData.WriteString(headTag)
	encodedData.WriteString(openVerTag)
	encodedData.WriteString(currentExportedVersion)
	encodedData.WriteString(closeVerTag)
	encodedData.WriteString(base64.StdEncoding.EncodeToString(buff.Bytes()))
	encodedData.WriteString(footTag)

	return encodedData.Bytes(), nil
}

// ImportPrivateIdentity generates a new PrivateIdentity from exported data.
func ImportPrivateIdentity(password string, data []byte) (PrivateIdentity, error) {
	var err error

	// Ensure the data is of sufficient length
	if len(data) == 0 {
		return PrivateIdentity{}, errors.New(noDataErr)
	}

	// Get data from between the header and footer tags
	data, err = getTagContents(data, headTag, footTag)
	if err != nil {
		return PrivateIdentity{}, errors.Errorf(noHeadFootTagsErr, err)
	}

	// Get the version number
	version, err := getTagContents(data, openVerTag, closeVerTag)
	if err != nil {
		return PrivateIdentity{}, errors.Errorf(noVersionTagErr, err)
	}

	if len(version) == 0 {
		return PrivateIdentity{}, errors.New(noVersionErr)
	}

	// Strip version number from the data
	data = data[len(version)+len(openVerTag)+len(closeVerTag):]

	// Return an error if no encoded data is found between the tags
	if len(data) == 0 {
		return PrivateIdentity{}, errors.New(noEncryptedData)
	}

	// Unmarshal the data according to its version
	decodeFunc, exists := decodeVersions[string(version)]
	if exists {
		return decodeFunc(password, data)
	}

	return PrivateIdentity{},
		errors.Errorf(wrongVersionErr, currentExportedVersion, version)
}

// encrypt generates a salt and encrypts the PrivateIdentity with the user's
// password and Argon2 parameters.
func (i PrivateIdentity) encrypt(password string, params backup.Params,
	csprng io.Reader) (encryptedData, salt []byte, err error) {
	// Generate salt used for key derivation
	salt, err = makeSalt(csprng)
	if err != nil {
		return nil, nil, err
	}

	// Derive key used to encrypt data
	key := deriveKey(password, salt, params)

	// Marshal identity data to be encrypted
	data := i.encode()

	// Encrypt the data
	encryptedData = encryptIdentity(data, key, csprng)

	return encryptedData, salt, nil
}

// decryptPrivateIdentity
func decryptPrivateIdentity(password string, data, salt []byte,
	params backup.Params) (PrivateIdentity, error) {
	// Derive decryption key
	key := deriveKey(password, salt, params)

	// Decrypt the data
	decryptedData, err := decryptIdentity(data, key)
	if err != nil {
		return PrivateIdentity{}, errors.Errorf(decryptionErr, err)
	}

	pi, err := decodePrivateIdentity(decryptedData)
	if err != nil {
		return PrivateIdentity{}, errors.Errorf(decodeErr, err)
	}

	return pi, nil
}

// encode marshals the public key, private key, and codeset along with a version
// number of this encoding. The length of the output is encodedLen.
//
// Marshalled data structure:
//
//	+---------+---------+---------------------+--------------------+
//	| Version | Codeset | ed25519 Private Key | ed25519 Public Key |
//	| 1 byte  | 1 byte  |      64 bytes       |      32 bytes      |
//	+---------+---------+---------------------+--------------------+
func (i PrivateIdentity) encode() []byte {
	buff := bytes.NewBuffer(nil)
	buff.Grow(encodedLen)

	buff.Write([]byte{currentEncryptedVersion})
	buff.Write([]byte{i.CodesetVersion})
	buff.Write(*i.Privkey)
	buff.Write(i.PubKey)

	return buff.Bytes()
}

// decodePrivateIdentity unmarshalls the private and public keys into a private
// identity from a marshaled version that was decrypted.
//
// Refer to [PrivateIdentity.encode] for the structure.
func decodePrivateIdentity(data []byte) (PrivateIdentity, error) {
	if len(data) != encodedLen {
		return PrivateIdentity{}, errors.Errorf(
			unmarshalDataLenErr, encodedLen, len(data))
	}
	buff := bytes.NewBuffer(data)

	version := buff.Next(versionLen)[0]
	if version != currentEncryptedVersion {
		return PrivateIdentity{}, errors.Errorf(
			versionMismatchErr, version, currentEncryptedVersion)
	}

	codesetVersion := buff.Next(codesetLen)[0]
	privKey := ed25519.PrivateKey(buff.Next(ed25519.PrivateKeySize))
	pubKey := ed25519.PublicKey(buff.Next(ed25519.PublicKeySize))
	identity, err := codename.ConstructIdentity(pubKey, codesetVersion)
	if err != nil {
		return PrivateIdentity{}, err
	}

	pi := PrivateIdentity{
		codename.PrivateIdentity{
			Privkey:  &privKey,
			Identity: identity,
		},
	}

	return pi, nil
}

// getTagContents returns the bytes between the two tags. An error is returned
// if one or more tags cannot be found or closing tag precedes the opening tag.
func getTagContents(b []byte, openTag, closeTag string) ([]byte, error) {
	// Search for opening tag
	openIndex := strings.Index(string(b), openTag)
	if openIndex < 0 {
		return nil, errors.New(noOpenTagErr)
	}

	// Search for closing tag
	closeIndex := strings.Index(string(b), closeTag)
	if closeIndex < 0 {
		return nil, errors.New(noCloseTagErr)
	}

	// Return an error if the closing tag comes first
	if openIndex > closeIndex {
		return nil, errors.New(swappedTagErr)
	}

	return b[openIndex+len(openTag) : closeIndex], nil
}
