////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package contact

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"encoding/base64"
	"encoding/binary"
	"strings"

	"github.com/pkg/errors"
	"github.com/skip2/go-qrcode"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/primitives/fact"
	"gitlab.com/xx_network/primitives/id"
	"golang.org/x/crypto/blake2b"
)

// Tags indicate the start and end of data. The tags must only contain printable
// ASCII characters.
const (
	headTag     = "<xxc" // Indicates the start of the encoded data
	footTag     = "xxc>" // Indicates the end of the encoded data
	openVerTag  = "("    // Indicates the start of the encoding version number
	closeVerTag = ")"    // Indicates the end of the encoding version number
)

// Sizes
const (
	fingerprintLength = 15 // Size, in bytes, of the fingerprint
	sizeLength        = 2  // Size, in bytes, of object sizes
	checksumLength    = 16 // Size, in bytes, of checksum
)

// Unmarshal errors
const (
	emptyBufferErr    = "Contact Unmarshal: buffer empty"
	emptyDataErr      = "Contact Unmarshal: no encoded data found"
	noTagsErr         = "Contact Unmarshal: data not found: %+v"
	noVersionErr      = "Contact Unmarshal: version not found: %+v"
	wrongVersionErr   = "Contact Unmarshal: incompatible version %s <= %s expected"
	base64DecodeErr   = "Contact Unmarshal: could not base64 decode: %+v"
	idUnmarshalErr    = "Contact Unmarshal: ID failed: %v"
	dhKeyUnmarshalErr = "Contact Unmarshal: DhPubKey failed: %+v"
	factsUnmarshalErr = "Contact Unmarshal: fact list failed: %+v"
	checksumErr       = "Contact Unmarshal: failed to verify checksum"
)

// Tag errors
const (
	noOpenTagErr  = "missing opening tag"
	noCloseTagErr = "missing closing tag"
	swappedTagErr = "tags in wrong order"
)

// Current version of the Contact marshal encoding
const currentVersion = "2"

// map of Contact encoding version numbers to their unmarshal functions.
var unmarshalVersions = map[string]func([]byte) (Contact, error){
	"0":            unmarshalVer0,
	"1":            unmarshalVer1,
	currentVersion: unmarshalVer2,
}

// Contact implements the Contact interface defined in interface/contact.go,
// in go, the structure is meant to be edited directly, the functions are for
// bindings compatibility.
type Contact struct {
	ID             *id.ID
	DhPubKey       *cyclic.Int
	OwnershipProof []byte
	Facts          fact.FactList
}

// ReadContact reads and unmarshal the contact from file and returns the
// marshaled ID and DH public key.
func ReadContactFromFile(contactFileData []byte) ([]byte, []byte, error) {

	c, err := Unmarshal(contactFileData)
	if err != nil {
		return nil, nil, errors.Errorf("Failed to unmarshal contact: %+v", err)
	}

	dhPubKeyJson, err := c.DhPubKey.MarshalJSON()
	if err != nil {
		return nil, nil, errors.Errorf("Failed to marshal contact DH public key: %+v", err)
	}

	return c.ID.Marshal(), dhPubKeyJson, nil
}

// Marshal saves the Contact in a compact binary format with base 64 encoding.
// The data has a header and footer that specify the format version and allow
// the data to be recognized in a stream of data. The format has the following
// structure.
//
// +----------------+---------------------------------------------------------------------------------------------------+--------+
// |     header     |                                     contact data                                                  | footer |
// +------+---------+----------+----------+----------+-----------------+----------------+---------+----------+----------+--------+
// | Open |         |    ID    | DhPubKey |          | OwnershipProof  |                |  Facts  |          | checksum | Close  |
// | Tag  | Version |          |   size   | DhPubKey |      size       | OwnershipProof |   size  | FactList |          |  Tag   |
// |      |         | 33 bytes |  2 bytes |          |     2 bytes     |                | 2 bytes |          | 16 bytes |        |
// +------+---------+----------+----------+----------+-----------------+----------------+---------+----------+----------+--------+
// |     string     |                                    base 64 encoded                                                | string |
// +----------------+---------------------------------------------------------------------------------------------------+--------+
func (c Contact) Marshal() []byte {
	var buff bytes.Buffer

	// Write ID
	if c.ID != nil {
		buff.Write(c.ID.Marshal())
	} else {
		// Handle nil ID
		buff.Write(make([]byte, id.ArrIDLen))
	}

	// Write size of DhPubKey
	b := make([]byte, sizeLength)
	var dhPubKey []byte
	if c.DhPubKey != nil {
		dhPubKey = c.DhPubKey.BinaryEncode()
		binary.PutVarint(b, int64(len(dhPubKey)))
	}
	buff.Write(b)

	// Write DhPubKey
	buff.Write(dhPubKey)

	// Write size of OwnershipProof
	b = make([]byte, sizeLength)
	binary.PutVarint(b, int64(len(c.OwnershipProof)))
	buff.Write(b)

	// Write OwnershipProof
	buff.Write(c.OwnershipProof)

	// Write length of Facts
	b = make([]byte, sizeLength)
	factList := c.Facts.Stringify()
	binary.PutVarint(b, int64(len(factList)))
	buff.Write(b)

	// Write fact list
	buff.Write([]byte(factList))

	// Generate and write checksum
	buff.Write(c.GetChecksum())

	// Base 64 encode buffer
	encodedBuff := make([]byte, base64.StdEncoding.EncodedLen(buff.Len()))
	base64.StdEncoding.Encode(encodedBuff, buff.Bytes())

	// Add header tag, version number, and footer tag
	encodedBuff = append([]byte(headTag+openVerTag+currentVersion+closeVerTag), encodedBuff...)
	encodedBuff = append(encodedBuff, []byte(footTag)...)

	return encodedBuff
}

// Unmarshal decodes the byte slice produced by Contact.Marshal into a Contact.
func Unmarshal(b []byte) (Contact, error) {
	// Create empty client
	c := Contact{DhPubKey: &cyclic.Int{}}
	var err error

	// Ensure the data is of sufficient length
	if len(b) <= 0 {
		return c, errors.New(emptyBufferErr)
	}

	// Get data from between the header and footer tags
	b, err = getTagContents(b, headTag, footTag)
	if err != nil {
		return c, errors.Errorf(noTagsErr, err)
	}

	// Get the version number
	version, err := getTagContents(b, openVerTag, closeVerTag)
	if err != nil {
		return c, errors.Errorf(noVersionErr, err)
	}

	// Strip version number from the data
	b = b[len(version)+len(openVerTag)+len(closeVerTag):]

	// Return an error if no encoded data is found between the tags
	if len(b) <= 0 {
		return c, errors.New(emptyDataErr)
	}

	// Unmarshal the data according to its version
	unmarshalFunc, exists := unmarshalVersions[string(version)]
	if exists {
		return unmarshalFunc(b)
	}

	return c, errors.Errorf(wrongVersionErr, version, currentVersion)
}

// GetChecksum generates a 16-byte checksum of the Contact.
func (c Contact) GetChecksum() []byte {
	h, _ := blake2b.New256(nil)

	// Hash data
	if c.ID != nil {
		h.Write(c.ID.Marshal())
	}

	if c.DhPubKey != nil {
		h.Write(c.DhPubKey.Bytes())
	}

	h.Write(c.OwnershipProof)

	h.Write([]byte(c.Facts.Stringify()))

	data := h.Sum(nil)

	return data[:checksumLength]
}

// GetFingerprint creates a 15 character long fingerprint of the contact off of
// the ID and DH public key.
func (c Contact) GetFingerprint() string {
	// Generate hash
	sha := crypto.SHA256
	h := sha.New()

	// Hash ID and DH public key
	if c.ID != nil {
		h.Write(c.ID.Bytes())
	}
	if c.DhPubKey != nil {
		h.Write(c.DhPubKey.Bytes())
	}
	data := h.Sum(nil)

	// Base64 encode hash and truncate it
	return base64.StdEncoding.EncodeToString(data)[:fingerprintLength]
}

// MakeQR generates a QR code PNG of the Contact.
func (c Contact) MakeQR(size int, level qrcode.RecoveryLevel) ([]byte, error) {
	qrCode, err := qrcode.Encode(string(c.Marshal()), level, size)
	if err != nil {
		return nil, errors.Errorf("failed to encode contact to QR code: %v", err)
	}

	return qrCode, nil
}

// String prints a string representation of the Contact for debugging and tests.
// This functions satisfies the fmt.Stringer interface.
func (c Contact) String() string {
	idString := ""
	if c.ID == nil {
		idString = "<nil>"
	} else {
		idString = c.ID.String()
	}

	dhPubKeyString := ""
	if c.DhPubKey == nil {
		dhPubKeyString = "<nil>"
	} else {
		dhPubKeyString = c.DhPubKey.Text(10)
	}

	return "ID: " + idString +
		"  DhPubKey: " + dhPubKeyString +
		"  OwnershipProof: " + base64.StdEncoding.EncodeToString(c.OwnershipProof) +
		"  Facts: " + c.Facts.Stringify()
}

// Equal determines if the two contacts have the same values.
func Equal(a, b Contact) bool {
	if (a.ID == nil && b.ID != nil) || (a.ID != nil && b.ID == nil) {
		return false
	}
	if (a.DhPubKey == nil && b.DhPubKey != nil) || (a.DhPubKey != nil && b.DhPubKey == nil) {
		return false
	}
	return ((a.ID == nil && b.ID == nil) || a.ID.Cmp(b.ID)) &&
		((a.DhPubKey == nil && b.DhPubKey == nil) || a.DhPubKey.Cmp(b.DhPubKey) == 0) &&
		hmac.Equal(a.OwnershipProof, b.OwnershipProof) &&
		a.Facts.Stringify() == b.Facts.Stringify()
}

// getTagContents returns the bytes between the two tags. An error is returned
// if one ore more tags cannot be found or closing tag precedes the opening tag.
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
