///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package singleUse

import (
	"encoding/binary"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/hash"
)

const responseKeySalt = "singleUseResponseKeySalt"

// NewResponseKey generates the key for the response message that corresponds
// with the given key number.
func NewResponseKey(dhKey *cyclic.Int, keyNum uint64) []byte {
	// Create new hash
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.ERROR.Panicf("Failed to create new hash for single-use response "+
			"key: %v", err)
	}

	keyNumBytes := make([]byte, binary.MaxVarintLen64)
	binary.BigEndian.PutUint64(keyNumBytes, keyNum)

	// Hash the DH key, key number, and salt
	h.Write(dhKey.Bytes())
	h.Write(keyNumBytes)
	h.Write([]byte(responseKeySalt))

	// Get hash bytes
	return h.Sum(nil)
}
