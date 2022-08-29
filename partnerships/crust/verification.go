////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package crust

import (
	"crypto"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"hash"
	"io"
)

// SignVerification signs the user's username and reception public key, hashed together.
func SignVerification(rand io.Reader, udPrivKey *rsa.PrivateKey,
	username string, receptionPubKey []byte) ([]byte, error) {
	// Hash username
	usernameHash := hashUsername(username)

	// Create hash to sign on
	opts := rsa.NewDefaultOptions()
	opts.Hash = crypto.SHA256
	hashed := makeVerificationSignatureHash(usernameHash, receptionPubKey,
		opts.Hash.New())

	// Return signature
	return rsa.Sign(rand, udPrivKey, opts.Hash, hashed, opts)
}

// VerifyVerificationSignature verifies the signature provided from SignVerification.
func VerifyVerificationSignature(pubKey *rsa.PublicKey,
	username string, receptionPubKey, signature []byte) error {

	// Hash username
	usernameHash := hashUsername(username)

	// Create hash that was signed
	opts := rsa.NewDefaultOptions()
	opts.Hash = crypto.SHA256
	hashed := makeVerificationSignatureHash(usernameHash, receptionPubKey,
		opts.Hash.New())

	// Verify signature
	return rsa.Verify(pubKey, opts.Hash, hashed, signature, opts)
}

// makeVerificationSignatureHash is a helper function shared between
// SignVerification and VerifyVerificationSignature. This creates the concatenation of
// the username hash (created using hashUsername) and the reception public key.
func makeVerificationSignatureHash(usernameHash, receptionPubKey []byte, h hash.Hash) []byte {
	h.Write(receptionPubKey)
	h.Write(usernameHash)
	return h.Sum(nil)
}
