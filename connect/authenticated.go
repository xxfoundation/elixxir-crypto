////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package connect

import (
	"github.com/pkg/errors"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"gitlab.com/xx_network/crypto/xx"
	"gitlab.com/xx_network/primitives/id"
	"io"
)

// Sign creates a signature authenticating an identity for a connection.
func Sign(rng io.Reader, rsaPrivKey *rsa.PrivateKey,
	connectionFp []byte) ([]byte, error) {
	// The connection fingerprint (hashed) will be used as a nonce
	opts := rsa.NewDefaultOptions()
	h := opts.Hash.New()
	h.Write(connectionFp)
	nonce := h.Sum(nil)

	// Sign the connection fingerprint
	return rsa.Sign(rng, rsaPrivKey,
		opts.Hash, nonce, opts)

}

// Verify takes a signature for an authentication attempt
// and verifies the information.
func Verify(partnerId *id.ID,
	signature, connectionFp, rsaPubKeyPem, salt []byte) error {
	// Process the PEM encoded public key to an rsa.PublicKey object
	partnerPubKey, err := rsa.LoadPublicKeyFromPem(rsaPubKeyPem)
	if err != nil {
		return err
	}

	// Verify the partner's known ID against the information passed
	// along the wire
	partnerWireId, err := xx.NewID(partnerPubKey, salt, id.User)
	if err != nil {
		return err
	}

	if !partnerId.Cmp(partnerWireId) {
		return errors.New("Failed confirm partner's ID over the wire")
	}

	// Hash the connection fingerprint
	opts := rsa.NewDefaultOptions()
	h := opts.Hash.New()
	h.Write(connectionFp)
	nonce := h.Sum(nil)

	// Verify the signature
	err = rsa.Verify(partnerPubKey, opts.Hash, nonce, signature, opts)
	if err != nil {
		return err
	}

	return nil

}
