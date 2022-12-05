////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package broadcast

import (
	"bytes"
	cryptoCipher "crypto/cipher"
	"encoding/base64"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/backup"
	"gitlab.com/elixxir/crypto/rsa"
	"gitlab.com/xx_network/primitives/id"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
	"strings"
)

// Error messages.
const (
	// portablePrivKey.export
	encryptErr = "could not encrypt channel private key: %+v"

	// ImportPrivateKey
	noDataErr         = "len of data is 0"
	noHeadFootTagsErr = "invalid format: %+v"
	noVersionTagErr   = "version tags not found: %+v"
	noVersionErr      = "version not found"
	noEncryptedData   = "no encrypted data found"
	wrongVersionErr   = "version must be %s or lower; received version %q"

	// portablePrivKey.decrypt
	decryptionErr = "could not decrypt channel private key data: %+v"
	decodeErr     = "could not decode decrypted channel private key data: %+v"

	// getTagContents
	noOpenTagErr  = "missing opening tag"
	noCloseTagErr = "missing closing tag"
	swappedTagErr = "tags in wrong order"

	// portablePrivKey.decode
	unmarshalDataLenErr = "data must be at least %d bytes; received %d bytes"
	versionMismatchErr  = "version received %d; version %d required"
	decodePemErr        = "could not get RSA private key: %+v"
)

// Tags indicate the start and end of data. The tags must only contain printable
// ASCII characters.
const (
	headTag     = "<xxChannelPrivateKey" // Start of the encoded data
	footTag     = "xxChannelPrivateKey>" // End of the encoded data
	openVerTag  = "("                    // Start of the encoding version number
	closeVerTag = ")"                    // End of the encoding version number
)

// Data lengths.
const (
	versionLen = 1

	// Minimum length of the encoded output of portablePrivKey.encode. The
	// actual length depends on the size of the RSA private key.
	encodedLenMin = versionLen + id.ArrIDLen

	// Minimum length of the data part of the exported string returned by
	// portablePrivKey.encode. The actual length depends on the size of the RSA
	// private key.
	exportedLenMin = privKeyPasswordSaltLen + backup.ParamsLen + encodedLenMin

	// keyLen is the length of the key used for encryption
	keyLen = chacha20poly1305.KeySize

	// privKeyPasswordSaltLen is the length of the salt used in key generation.
	// The recommended size is 16 bytes, mentioned here:
	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-argon2-04#section-3.1
	privKeyPasswordSaltLen = 16
)

// The current version of the encoded format returned by portablePrivKey.encode.
const currentEncryptedVer = uint8(0)

// Current version of the string returned by ExportPrivateKey.
const currentExportedVer = "0"

// Map of exported encoding version numbers to their decoding functions.
var decodeVersions = map[string]func(
	password string, data []byte) (*portablePrivKey, error){
	currentExportedVer: decodeVer0,
}

type portablePrivKey struct {
	channelID *id.ID
	privKey   rsa.PrivateKey
}

// ExportPrivateKey exports the channel's RSA private key into a portable
// encrypted string that can be used to restore it later.
//
// Each call to ExportPrivateKey produces a different encrypted packet
// regardless if the same password is used for the same channel. It cannot be
// determined which channel the payload is for nor that two payloads are for the
// same channel.
//
// The passwords between each call are not related. They can be the same or
// different with no adverse impact on the security properties.
func ExportPrivateKey(channelID *id.ID, privKey rsa.PrivateKey,
	encryptionPassword string, csprng io.Reader) ([]byte, error) {
	ppk := &portablePrivKey{channelID, privKey}
	return ppk.export(encryptionPassword, backup.DefaultParams(), csprng)
}

// ExportPrivateKeyCustomParams exports the channel's RSA private key into a
// portable encrypted string that can be used to restore it later using custom
// Argon 2 parameters.
func ExportPrivateKeyCustomParams(channelID *id.ID, privKey rsa.PrivateKey,
	encryptionPassword string, params backup.Params, csprng io.Reader) (
	[]byte, error) {
	ppk := &portablePrivKey{channelID, privKey}
	return ppk.export(encryptionPassword, params, csprng)
}

// export encrypts and channel's RSA private key and outputs it with the channel
// ID, encryption salt, and key derivation (argon) parameters as a portable
// string.
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
func (ppk *portablePrivKey) export(
	encryptionPassword string, params backup.Params, csprng io.Reader) ([]byte, error) {

	// Encrypt the portablePrivKey with the user password
	encryptedData, salt, err := ppk.encrypt(encryptionPassword, params, csprng)
	if err != nil {
		return nil, errors.Errorf(encryptErr, err)
	}

	// Add encryption metadata and encrypted data to buffer
	buff := bytes.NewBuffer(nil)
	buff.Grow(exportedLenMin)
	buff.Write(salt)
	buff.Write(params.Marshal())
	buff.Write(encryptedData)

	// Add header tag, version number, and footer tag
	encodedData := bytes.NewBuffer(nil)
	encodedData.WriteString(headTag)
	encodedData.WriteString(openVerTag)
	encodedData.WriteString(currentExportedVer)
	encodedData.WriteString(closeVerTag)
	encodedData.WriteString(base64.StdEncoding.EncodeToString(buff.Bytes()))
	encodedData.WriteString(footTag)

	return encodedData.Bytes(), nil
}

// ImportPrivateKey returns the channel ID and private RSA key in the encrypted
// portable string.
func ImportPrivateKey(
	encryptionPassword string, data []byte) (*id.ID, rsa.PrivateKey, error) {
	var err error

	// Ensure the data is of sufficient length
	if len(data) == 0 {
		return nil, nil, errors.New(noDataErr)
	}

	// Get data from between the header and footer tags
	data, err = getTagContents(data, headTag, footTag)
	if err != nil {
		return nil, nil, errors.Errorf(noHeadFootTagsErr, err)
	}

	// Get the version number
	version, err := getTagContents(data, openVerTag, closeVerTag)
	if err != nil {
		return nil, nil, errors.Errorf(noVersionTagErr, err)
	}

	if len(version) == 0 {
		return nil, nil, errors.New(noVersionErr)
	}

	// Strip version number from the data
	data = data[len(version)+len(openVerTag)+len(closeVerTag):]

	// Return an error if no encoded data is found between the tags
	if len(data) == 0 {
		return nil, nil, errors.New(noEncryptedData)
	}

	// Unmarshal the data according to its version
	decodeFunc, exists := decodeVersions[string(version)]
	if exists {
		ppk, err2 := decodeFunc(encryptionPassword, data)
		if err2 != nil {
			return nil, nil, err2
		}
		return ppk.channelID, ppk.privKey, nil
	}

	return nil, nil,
		errors.Errorf(wrongVersionErr, currentExportedVer, version)
}

// encrypt generates a salt and encrypts the portablePrivKey with the user's
// password and Argon2 parameters.
func (ppk *portablePrivKey) encrypt(password string, params backup.Params,
	csprng io.Reader) (encryptedData, salt []byte, err error) {
	// Generate salt used for key derivation
	salt, err = makeSalt(csprng)
	if err != nil {
		return nil, nil, err
	}

	// Derive key used to encrypt data via Argon2
	key := deriveKey(password, salt, params)

	// Marshal portablePrivKey data to be encrypted
	data := ppk.encode()

	// Encrypt the data
	encryptedData = encryptPrivateKey(data, key, csprng)

	return encryptedData, salt, nil
}

// decrypt derives the key from the password and salt and uses it to decrypt the
// channel private key.
func (ppk *portablePrivKey) decrypt(
	password string, data, salt []byte, params backup.Params) error {
	// Derive decryption key
	key := deriveKey(password, salt, params)

	// Decrypt the data
	decryptedData, err := decryptPrivateKey(data, key)
	if err != nil {
		return errors.Errorf(decryptionErr, err)
	}

	err = ppk.decode(decryptedData)
	if err != nil {
		return errors.Errorf(decodeErr, err)
	}

	return nil
}

// encode marshals the channel ID and private key along with a version number
// of this encoding.
//
// Marshalled data structure:
//
//	+---------+------------+---------------------+
//	| Version | Channel ID | RSA Private Key PEM |
//	| 1 byte  |  33 bytes  |       variable      |
//	+---------+------------+---------------------+
func (ppk *portablePrivKey) encode() []byte {
	buff := bytes.NewBuffer(nil)
	buff.Grow(versionLen + id.ArrIDLen)

	buff.Write([]byte{currentEncryptedVer})
	buff.Write(ppk.channelID.Marshal())
	buff.Write(ppk.privKey.MarshalPem())

	return buff.Bytes()
}

// decode unmarshalls the data into a channel ID and its private RSA key.
//
// Refer to portablePrivKey.encode for the structure.
func (ppk *portablePrivKey) decode(data []byte) error {
	if len(data) < encodedLenMin {
		return errors.Errorf(unmarshalDataLenErr, encodedLenMin, len(data))
	}
	buff := bytes.NewBuffer(data)
	var err error

	version := buff.Next(versionLen)[0]
	if version != currentEncryptedVer {
		return errors.Errorf(versionMismatchErr, version, currentEncryptedVer)
	}

	ppk.channelID, err = id.Unmarshal(buff.Next(id.ArrIDLen))
	if err != nil {
		return err
	}

	ppk.privKey, err = rsa.GetScheme().UnmarshalPrivateKeyPEM(buff.Bytes())
	if err != nil {
		return errors.Errorf(decodePemErr, err)
	}

	return nil
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

////////////////////////////////////////////////////////////////////////////////
// Cryptography                                                               //
////////////////////////////////////////////////////////////////////////////////

// Error messages.
const (
	// decryptPrivateKey
	readNonceLenErr        = "read %d bytes, too short to decrypt"
	decryptWithPasswordErr = "cannot decrypt with password: %+v"

	// makeSalt
	readSaltErr     = "could not read RNG for salt: %+v"
	saltNumBytesErr = "expected %d bytes for salt, found %d bytes"
)

// encryptPrivateKey encrypts a channel's private key using XChaCha20-Poly1305.
// The resulting encrypted data has the nonce prepended to it.
func encryptPrivateKey(data, key []byte, csprng io.Reader) []byte {
	chaCipher := initChaCha20Poly1305Pk(key)
	nonce := make([]byte, chaCipher.NonceSize())
	if _, err := io.ReadFull(csprng, nonce); err != nil {
		jww.FATAL.Panicf("Could not generate nonce %+v", err)
	}
	ciphertext := chaCipher.Seal(nonce, nonce, data, nil)
	return ciphertext
}

// decryptPrivateKey decrypts the channel private key using XChaCha20-Poly1305.
func decryptPrivateKey(data, key []byte) ([]byte, error) {
	chaCipher := initChaCha20Poly1305Pk(key)
	nonceLen := chaCipher.NonceSize()
	if (len(data) - nonceLen) <= 0 {
		return nil, errors.Errorf(readNonceLenErr, len(data))
	}

	// The first nonceLen bytes of ciphertext are the nonce.
	nonce, ciphertext := data[:nonceLen], data[nonceLen:]
	plaintext, err := chaCipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.Errorf(decryptWithPasswordErr, err)
	}
	return plaintext, nil
}

// initChaCha20Poly1305Pk returns a XChaCha20-Poly1305 cipher.AEAD that uses the
// given password hashed into a 256-bit key.
func initChaCha20Poly1305Pk(key []byte) cryptoCipher.AEAD {
	pwHash := blake2b.Sum256(key)
	chaCipher, err := chacha20poly1305.NewX(pwHash[:])
	if err != nil {
		jww.FATAL.Panicf("Could not init XChaCha20Poly1305 mode: %+v", err)
	}

	return chaCipher
}

// deriveKey derives a key from a user supplied password and a salt via the
// Argon2 algorithm.
func deriveKey(password string, salt []byte, params backup.Params) []byte {
	return argon2.IDKey([]byte(password), salt,
		params.Time, params.Memory, params.Threads, keyLen)
}

// makeSalt generates a salt used for key generation.
func makeSalt(csprng io.Reader) ([]byte, error) {
	b := make([]byte, privKeyPasswordSaltLen)
	size, err := csprng.Read(b)
	if err != nil {
		return nil, errors.Errorf(readSaltErr, err)
	} else if size != privKeyPasswordSaltLen {
		return nil, errors.Errorf(saltNumBytesErr, privKeyPasswordSaltLen, size)
	}

	return b, nil
}
