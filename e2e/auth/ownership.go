/* Copyright 2020 xx network SEZC

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.

*/

package auth

import (
	"bytes"
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

	return bytes.Equal(generatedProof, proof)
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
