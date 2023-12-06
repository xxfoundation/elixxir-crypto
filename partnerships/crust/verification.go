////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package crust

import (
	"crypto"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"hash"
	"io"
)

// SignVerification signs the user's username and reception public key, hashed together.
func SignVerification(rand io.Reader, udPrivKey *rsa.PrivateKey,
	username string, receptionPubKey *rsa.PublicKey) ([]byte, error) {
	// Hash username
	usernameHash := HashUsername(username)

	// Create hash to sign on
	opts := rsa.NewDefaultOptions()
	opts.Hash = crypto.SHA256
	hashed := makeVerificationSignatureHash(usernameHash,
		receptionPubKey.N.Bytes(), opts.Hash.New())

	// Return signature
	return rsa.Sign(rand, udPrivKey, opts.Hash, hashed, opts)
}

// VerifyVerificationSignature verifies the signature provided from SignVerification.
func VerifyVerificationSignature(pubKey *rsa.PublicKey,
	usernameHash []byte, receptionPubKey *rsa.PublicKey, signature []byte) error {

	// Create hash that was signed
	opts := rsa.NewDefaultOptions()
	opts.Hash = crypto.SHA256
	hashed := makeVerificationSignatureHash(usernameHash,
		receptionPubKey.N.Bytes(), opts.Hash.New())

	// Verify signature
	return rsa.Verify(pubKey, opts.Hash, hashed, signature, opts)
}

// makeVerificationSignatureHash is a helper function shared between
// SignVerification and VerifyVerificationSignature. This creates the concatenation of
// the username hash (created using HashUsername) and the reception public key.
func makeVerificationSignatureHash(usernameHash, receptionPubKey []byte, h hash.Hash) []byte {
	h.Write(receptionPubKey)
	h.Write(usernameHash)
	return h.Sum(nil)
}
