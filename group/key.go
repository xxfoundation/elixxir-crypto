////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package group

import (
	"encoding/base64"
	"encoding/binary"
	"github.com/pkg/errors"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"
	"hash"
	"time"
)

// CryptKeyLen is the length, in bytes, of the KDF key.
const CryptKeyLen = 32

// Error messages.
const (
	readHkdfErr    = "New KDF Key: failed to read key bytes: %+v"
	readHkdfLenErr = "New KDF Key: length of read bytes %d != %d expected"
)

// CryptKey is the 256-bit key used for encryption/decryption.
type CryptKey [CryptKeyLen]byte

// NewKdfKey produces a new 256-bit using HKDF.
func NewKdfKey(groupKey Key, epoch uint32, salt [SaltLen]byte) (CryptKey, error) {
	// Underlying hash function
	h := func() hash.Hash {
		h, _ := blake2b.New256(nil)
		return h
	}

	// Generate secret by appending the group key and the epoch bytes
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, epoch)
	secret := append(groupKey[:], b...)

	// Generate a 256-bit key
	hkdfReader := hkdf.New(h, secret, salt[:], nil)
	var key CryptKey
	n, err := hkdfReader.Read(key[:])
	if err != nil {
		return key, errors.Errorf(readHkdfErr, err)
	} else if n != CryptKeyLen {
		return key, errors.Errorf(readHkdfLenErr, n, CryptKeyLen)
	}

	return key, nil
}

// Bytes returns the CryptKey as a byte slice.
func (ck CryptKey) Bytes() []byte {
	return ck[:]
}

// String returns the CryptKey as a base 64 encoded string. This functions
// satisfies the fmt.Stringer interface.
func (ck CryptKey) String() string {
	return base64.StdEncoding.EncodeToString(ck.Bytes())
}

const epochPeriod = 5 * time.Minute

// ComputeEpoch generates an epoch for the given time.
func ComputeEpoch(t time.Time) uint32 {
	return uint32(t.UnixNano() / int64(epochPeriod))
}
