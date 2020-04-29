////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package xx

import (
	"bytes"
	"crypto/rsa"
	"encoding/binary"
	"github.com/pkg/errors"
	"gitlab.com/elixxir/crypto/hash"
)

// Length of IDs
const idDataLen = 32
const IdLen = idDataLen + 1

// ID is a generic identifier to be used for different entities. The first 32
// bytes hold the ID data and the last byte holds the ID type.
type ID [IdLen]byte
type IDType uint8

const IDTypeGateway = IDType(uint(1))
const IDTypeServer = IDType(uint(2))
const IDTypeClient = IDType(uint(3))

// IntToBytes converts an integer to big endian byte slice
// Because int can be 32 or 64 bits, it is always treated
// as 64 for the purposes of this function.
func IntToBytes(x int) []byte {
	byteBuf := new(bytes.Buffer)
	// NOTE: binary.Write shouldn't ever error on any value of int64
	// so we don't handle returned errors.
	binary.Write(byteBuf, binary.BigEndian, int64(x))
	return byteBuf.Bytes()
}

// PublicKeyBytes converts an RSA public key to a byte representation
// Specifically N's bytes concatenated with the public exponent concatenated
// at the end
func PublicKeyBytes(key rsa.PublicKey) []byte {
	pkBytes := IntToBytes(key.E)
	pkBytes = append(pkBytes, key.N.Bytes()...)
	return pkBytes
}

// NewID creates a new ID by hashing the public key with a random 256-bit number
// and appending the ID type.
// ID's are used by cmix to identify users, gateways, servers, and other network
// services
// You should use this function with csprng:
//   rng := csprng.NewSystemRNG()
//   privk, err := rsa.GenerateKey(rng, 4096)
//   pubk := privk.PublicKey
//   // check err
//   salt, err := csprng.Generate(32, rng)
//   // check err
//   id, err := xx.NewID(pubk, salt, IDTypeGateway)
//   // check err
func NewID(key rsa.PublicKey, salt []byte, idType IDType) (*ID, error) {
	// Salt's must be 256bit
	if len(salt) != 32 {
		return nil, errors.New("salt must be 32 bytes")
	}
	// We don't support unknown ID Types
	if idType != IDTypeGateway &&
		idType != IDTypeServer && idType != IDTypeClient {
		return nil, errors.New("Unsupported ID Type")
	}

	h, err := hash.NewCMixHash()
	if err != nil {
		return nil, errors.Wrap(err, "Could not instantiate CMixHash")
	}

	pkBytes := PublicKeyBytes(key)

	h.Write(pkBytes)
	h.Write(salt)
	digest := h.Sum(nil)
	var newID ID
	for i := 0; i < idDataLen; i++ {
		newID[i] = digest[i]
	}
	newID[IdLen-1] = byte(idType)
	return &newID, nil
}
