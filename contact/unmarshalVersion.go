////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

// This file contains old versions of the Contact unmarshal function to maintain
// backwards compatibility.

package contact

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"

	"github.com/pkg/errors"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/primitives/fact"
	"gitlab.com/xx_network/primitives/id"
)

// unmarshalVer2 unmarshalers Contact encoding for version "2" using the
// following structure.
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
func unmarshalVer2(b []byte) (Contact, error) {
	// Create empty client
	c := Contact{DhPubKey: &cyclic.Int{}}

	// Create new decoder
	decoder := base64.NewDecoder(base64.StdEncoding, bytes.NewReader(b))

	// Create a new buffer from the data found between the open and close tags
	var buff bytes.Buffer
	_, err := buff.ReadFrom(decoder)
	if err != nil {
		return c, errors.Errorf(base64DecodeErr, err)
	}

	// Get and unmarshal ID
	c.ID, err = id.Unmarshal(buff.Next(id.ArrIDLen))
	if err != nil {
		return c, errors.Errorf(idUnmarshalErr, err)
	}

	// If the ID is equal to all zeroes, then set it to nil
	if *c.ID == (id.ID{}) {
		c.ID = nil
	}

	// Get and decode DhPubKey
	dhPubKeySize, _ := binary.Varint(buff.Next(sizeLength))
	if dhPubKeySize == 0 {
		// Handle nil key
		c.DhPubKey = nil
	} else {
		if err = c.DhPubKey.BinaryDecode(buff.Next(int(dhPubKeySize))); err != nil {
			return c, errors.Errorf(dhKeyUnmarshalErr, err)
		}
	}

	// Get OwnershipProof
	ownershipProofSize, _ := binary.Varint(buff.Next(sizeLength))
	if ownershipProofSize == 0 {
		// Handle nil OwnershipProof
		c.OwnershipProof = nil
	} else {
		c.OwnershipProof = buff.Next(int(ownershipProofSize))
	}

	// Get and unstringify fact list
	factsSize, _ := binary.Varint(buff.Next(sizeLength))
	c.Facts, _, err = fact.UnstringifyFactList(string(buff.Next(int(factsSize))))
	if err != nil {
		return c, errors.Errorf(factsUnmarshalErr, err)
	}

	// Get the checksum
	checksum := buff.Next(checksumLength)

	// Verify matching checksum
	if !hmac.Equal(c.GetChecksum(), checksum) {
		return c, errors.New(checksumErr)
	}

	return c, nil
}

// unmarshalVer1 unmarshalers Contact encoding for version "1" using the
// following structure. This version uses an MD5 hash instead of Blake.
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
func unmarshalVer1(b []byte) (Contact, error) {
	// Create empty client
	c := Contact{DhPubKey: &cyclic.Int{}}

	// Create new decoder
	decoder := base64.NewDecoder(base64.StdEncoding, bytes.NewReader(b))

	// Create a new buffer from the data found between the open and close tags
	var buff bytes.Buffer
	_, err := buff.ReadFrom(decoder)
	if err != nil {
		return c, errors.Errorf(base64DecodeErr, err)
	}

	// Get and unmarshal ID
	c.ID, err = id.Unmarshal(buff.Next(id.ArrIDLen))
	if err != nil {
		return c, errors.Errorf(idUnmarshalErr, err)
	}

	// If the ID is equal to all zeroes, then set it to nil
	if *c.ID == (id.ID{}) {
		c.ID = nil
	}

	// Get and decode DhPubKey
	dhPubKeySize, _ := binary.Varint(buff.Next(sizeLength))
	if dhPubKeySize == 0 {
		// Handle nil key
		c.DhPubKey = nil
	} else {
		if err = c.DhPubKey.BinaryDecode(buff.Next(int(dhPubKeySize))); err != nil {
			return c, errors.Errorf(dhKeyUnmarshalErr, err)
		}
	}

	// Get OwnershipProof
	ownershipProofSize, _ := binary.Varint(buff.Next(sizeLength))
	if ownershipProofSize == 0 {
		// Handle nil OwnershipProof
		c.OwnershipProof = nil
	} else {
		c.OwnershipProof = buff.Next(int(ownershipProofSize))
	}

	// Get and unstringify fact list
	factsSize, _ := binary.Varint(buff.Next(sizeLength))
	c.Facts, _, err = fact.UnstringifyFactList(string(buff.Next(int(factsSize))))
	if err != nil {
		return c, errors.Errorf(factsUnmarshalErr, err)
	}

	// Get the checksum
	checksum := buff.Next(checksumLength)

	// Verify matching checksum
	if !hmac.Equal(c.GetChecksumVer1(), checksum) {
		return c, errors.New(checksumErr)
	}

	return c, nil
}

// GetChecksum generates a 16-byte checksum of the Contact.
func (c Contact) GetChecksumVer1() []byte {
	h := md5.New()

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

// unmarshalVer0 unmarshalers Contact encoding for version "0" using the
// following structure.
//
// +----------------+---------------------------------------------------------------------------------------+--------+
// |     header     |                                     contact data                                      | footer |
// +------+---------+----------+----------------+---------+----------+----------+----------------+----------+--------+
// | Open |         | DhPubKey | OwnershipProof |  Facts  |    ID    |          |                |          | Close  |
// | Tag  | Version |   size   |      size      |   size  |          | DhPubKey | OwnershipProof | FactList |  Tag   |
// |      |    0    |  2 bytes |     2 bytes    | 2 bytes | 33 bytes |          |                |          |        |
// +------+---------+----------+----------------+---------+----------+----------+----------------+----------+--------+
// |     string     |                                    base 64 encoded                                    | string |
// +----------------+---------------------------------------------------------------------------------------+--------+
func unmarshalVer0(b []byte) (Contact, error) {
	// Create empty client
	c := Contact{DhPubKey: &cyclic.Int{}}

	// Create new decoder
	decoder := base64.NewDecoder(base64.StdEncoding, bytes.NewReader(b))

	// Create a new buffer from the data found between the open and close tags
	var buff bytes.Buffer
	_, err := buff.ReadFrom(decoder)
	if err != nil {
		return c, errors.Errorf(base64DecodeErr, err)
	}

	// Get size of each field
	dhPubKeySize, _ := binary.Varint(buff.Next(sizeLength))
	ownershipProofSize, _ := binary.Varint(buff.Next(sizeLength))
	factsSize, _ := binary.Varint(buff.Next(sizeLength))

	// Get and unmarshal ID
	c.ID, err = id.Unmarshal(buff.Next(id.ArrIDLen))
	if err != nil {
		return c, errors.Errorf(idUnmarshalErr, err)
	}

	// If the ID is equal to all zeroes, then set it to nil
	if *c.ID == (id.ID{}) {
		c.ID = nil
	}

	// Get and decode DhPubKey
	if dhPubKeySize == 0 {
		// Handle nil key
		c.DhPubKey = nil
	} else {
		dhKekBytes, err := convertOldCyclicIntDecode(buff.Next(int(dhPubKeySize)))
		if err != nil {
			return c, errors.Errorf(dhKeyUnmarshalErr, err)
		}
		if err = c.DhPubKey.BinaryDecode(dhKekBytes); err != nil {
			return c, errors.Errorf(dhKeyUnmarshalErr, err)
		}
	}

	// Get OwnershipProof
	if ownershipProofSize == 0 {
		// Handle nil OwnershipProof
		c.OwnershipProof = nil
	} else {
		c.OwnershipProof = buff.Next(int(ownershipProofSize))
	}

	// Get and unstringify fact list
	c.Facts, _, err = fact.UnstringifyFactList(string(buff.Next(int(factsSize))))
	if err != nil {
		return c, errors.Errorf(factsUnmarshalErr, err)
	}

	return c, nil
}

// convertOldCyclicIntDecode converts the old version of binary encoded cyclic
// int to the new version.
func convertOldCyclicIntDecode(b []byte) ([]byte, error) {
	buff := bytes.NewBuffer(b)
	fingerprint, err := binary.ReadUvarint(buff)
	if err != nil {
		return nil, errors.Errorf("failed to decode Int fingerprint: %+v", err)
	}

	valueBytes := buff.Bytes()

	buff = bytes.NewBuffer(nil)
	bb := make([]byte, 8)

	binary.LittleEndian.PutUint64(bb, fingerprint)
	buff.Write(bb)
	buff.Write(valueBytes)
	return buff.Bytes(), nil
}
