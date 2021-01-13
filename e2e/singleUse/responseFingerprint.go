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
	"gitlab.com/elixxir/primitives/format"
)

const responseFPConstant = "responseFPConstant"

func ResponseFingerprint(pubKey *cyclic.Int, keyNum uint64) format.Fingerprint {
	// Create fingerprint
	fp := format.Fingerprint{}
	copy(fp[:], makeHash(pubKey, keyNum, responseFPConstant))

	return fp
}

func makeHash(pubKey *cyclic.Int, keyNum uint64, constant string) []byte {
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.ERROR.Panicf("Failed to create hash: %v", err)
	}

	// Convert the key number to bytes
	buff := make([]byte, binary.MaxVarintLen64)
	binary.BigEndian.PutUint64(buff, keyNum)

	// Hash the key, number, and constant
	h.Write(pubKey.Bytes())
	h.Write(buff)
	h.Write([]byte(constant))

	return h.Sum(nil)
}
