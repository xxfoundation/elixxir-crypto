////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////
package auth

import (
	"bytes"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/diffieHellman"
	"gitlab.com/elixxir/crypto/hash"
)

const ownershipVector = "ownershipVector"
const ownershipFPVector = "ownershipFPVector"

// Ownership proofs allow users to build short proofs they own public DH keys
func MakeOwnershipProof(myHistoricalPrivKey, partnerHistoricalPubKey *cyclic.Int,
	grp *cyclic.Group) []byte {

	historicalBaseKey := diffieHellman.GenerateSessionKey(myHistoricalPrivKey,
		partnerHistoricalPubKey, grp)

	//suppress because we just panic and a nil hash will panic anyhow
	h, _ := hash.NewCMixHash()
	// This will panic if we got an error in the line above, but does nothing
	// if it worked.
	h.Reset()

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

// Ownership proofs allow users to build short proofs they own public DH keys
func MakeOwnershipProofFP(ownershipProof []byte) []byte {
	//suppress because we just panic and a nil hash will panic anyhow
	h, _ := hash.NewCMixHash()
	// This will panic if we got an error in the line above, but does nothing
	// if it worked.
	h.Reset()

	h.Write(ownershipProof)
	h.Write([]byte(ownershipFPVector))

	return h.Sum(nil)
}
