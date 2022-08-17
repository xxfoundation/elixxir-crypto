////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package crust

import (
	"gitlab.com/xx_network/crypto/signature/rsa"
	"hash"
	"io"
)

// todo docstring
func SignVerification(rand io.Reader, udPrivKey *rsa.PrivateKey,
	usernameHash, receptionPubKey []byte) ([]byte, error) {
	opts := rsa.NewDefaultOptions()
	hashed := makeVerificationSignatureHash(usernameHash, receptionPubKey,
		opts.Hash.New())

	return rsa.Sign(rand, udPrivKey, opts.Hash, hashed, opts)
}

// todo docstring
func VerifyVerificationSignature(pubKey *rsa.PublicKey,
	usernameHash, receptionPubKey, signature []byte) error {
	opts := rsa.NewDefaultOptions()
	hashed := makeVerificationSignatureHash(usernameHash, receptionPubKey,
		opts.Hash.New())

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
