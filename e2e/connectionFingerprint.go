////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package e2e

import (
	"bytes"
	"golang.org/x/crypto/blake2b"
)

// GenerateConnectionFingerprint that is the same on both sender and receiver side for E2e partners
func GenerateConnectionFingerprint(sendFp, receiveFp []byte) []byte {
	// Sort fingerprints
	var fps [][]byte
	if bytes.Compare(receiveFp, sendFp) == 1 {
		fps = [][]byte{sendFp, receiveFp}
	} else {
		fps = [][]byte{receiveFp, sendFp}
	}

	// Hash fingerprints
	h, _ := blake2b.New256(nil)
	for _, fp := range fps {
		h.Write(fp)
	}

	return h.Sum(nil)
}
