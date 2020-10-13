////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////
package auth

import (
	"bytes"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/diffieHellman"
	"gitlab.com/elixxir/crypto/hash"
)

const ownershipVector = "ownershipVector"

// Ownership proofs allow users to build short proofs they own public DH keys
func MakeOwnershipProof(myHistoricalPrivKey, partnerHistoricalPubKey *cyclic.Int,
	grp *cyclic.Group) []byte {

	historicalBaseKey := diffieHellman.GenerateSessionKey(myHistoricalPrivKey,
		partnerHistoricalPubKey, grp)

	h, err := hash.NewCMixHash()
	if err != nil {
		jww.FATAL.Panicf("Could not get hash: %+v", err)
	}

	h.Write(historicalBaseKey.Bytes())
	h.Write([]byte(ownershipVector))

	return h.Sum(nil)
}

// verifies that an ownership proof is valid
func VerifyOwnershipProof(myHistoricalPrivKey, partnerHistoricalPubKey *cyclic.Int,
	grp *cyclic.Group, proof []byte) bool {

	generatedProof := MakeOwnershipProof(myHistoricalPrivKey,
		partnerHistoricalPubKey, grp)

	return bytes.Equal(generatedProof, proof)
}
