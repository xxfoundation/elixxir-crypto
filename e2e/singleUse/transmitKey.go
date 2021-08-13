///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package singleUse

import (
	jww "github.com/spf13/jwalterweatherman"
	"git.xx.network/elixxir/crypto/cyclic"
	"git.xx.network/elixxir/crypto/hash"
)

const transmitKeySalt = "singleUseTransmitKeySalt"

// NewTransmitKey generates the key used for the transmission message.
func NewTransmitKey(dhKey *cyclic.Int) []byte {
	// Create new hash
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.ERROR.Panicf("Failed to create new hash for single-use "+
			"communication transmission key: %v", err)
	}

	// Hash the DH key and salt
	h.Write(dhKey.Bytes())
	h.Write([]byte(transmitKeySalt))

	// Get hash bytes
	return h.Sum(nil)
}
