////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                           //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file                                                               //
////////////////////////////////////////////////////////////////////////////////

package singleUse

import (
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/elixxir/primitives/format"
)

const transmitFPConstant = "transmitFPConstant"

func TransmitFingerprint(pubKey *cyclic.Int) format.Fingerprint {
	// Create new hash
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.ERROR.Panicf("Failed to create hash: %v", err)
	}

	// Hash the key and constant
	h.Write(pubKey.Bytes())
	h.Write([]byte(transmitFPConstant))
	keyHash := h.Sum(nil)

	// Create fingerprint
	fp := format.Fingerprint{}
	copy(fp[:], keyHash)

	return fp
}
