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
func PublicKeyBytes(key *rsa.PublicKey) []byte {
	pkBytes := IntToBytes(key.E)
	pkBytes = append(pkBytes, key.N.Bytes()...)
	return pkBytes
}
