////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package auth

import (
	"crypto/hmac"

	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/diffieHellman"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/elixxir/primitives/format"
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

	return hmac.Equal(generatedProof, proof)
}

// Ownership proofs allow users to build short proofs they own public DH keys
func MakeOwnershipProofFP(ownershipProof []byte) format.Fingerprint {
	//suppress because we just panic and a nil hash will panic anyhow
	h, _ := hash.NewCMixHash()
	// This will panic if we got an error in the line above, but does nothing
	// if it worked.
	h.Reset()

	h.Write(ownershipProof)
	h.Write([]byte(ownershipFPVector))

	sum := h.Sum(nil)
	// Fingerprints require the first bit to be 0
	sum[0] &= 0x7F

	fp := format.Fingerprint{}
	copy(fp[:], sum)

	return fp
}
