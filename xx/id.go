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
	"gitlab.com/elixxir/primitives/id"
)

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
func NewID(key rsa.PublicKey, salt []byte, idType id.Type) (*id.ID, error) {
	// Salt's must be 256bit
	if len(salt) != 32 {
		return nil, errors.New("salt must be 32 bytes")
	}
	// We don't support unknown ID Types
	if idType != id.Gateway &&
		idType != id.Node && idType != id.User {
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
	var newID id.ID
	for i := 0; i < id.ArrIDLen-1; i++ {
		newID[i] = digest[i]
	}
	newID[id.ArrIDLen-1] = byte(idType)
	return &newID, nil
}
