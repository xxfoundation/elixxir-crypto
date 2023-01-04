////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package rsa

import (
	gorsa "crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"gitlab.com/xx_network/crypto/large"
	oldrsa "gitlab.com/xx_network/crypto/signature/rsa"
	"io"
)

const (
	// ELength is the length in bytes that the RSA Public Key's E component
	// serializes to.
	ELength = 4
)

type public struct {
	gorsa.PublicKey
}

// EncryptPKCS1v15 encrypts the given message with RSA and the padding scheme
// from PKCS #1 v1.5. The message must be no longer than the length of the
// public modulus minus 11 bytes.
//
// The random parameter is used as a source of entropy to ensure that encrypting
// the same message twice doesn't result in the same ciphertext.
//
// WARNING: use of this function to encrypt plaintexts other than session keys
// is dangerous. Use RSA OAEP in new protocols.
//
// This function uses the Go standard crypto/rsa implementation.
func (pub *public) EncryptPKCS1v15(
	random io.Reader, msg []byte) ([]byte, error) {
	return gorsa.EncryptPKCS1v15(random, &pub.PublicKey, msg)
}

// GetGoRSA returns the public key in the standard Go crypto/rsa format.
func (pub *public) GetGoRSA() *gorsa.PublicKey {
	return &pub.PublicKey
}

// GetOldRSA returns the public key in the old wrapper format for RSA that was
// used in xx project.
//
// Deprecated: Only use for compatibility during the change.
func (pub *public) GetOldRSA() *oldrsa.PublicKey {
	return &oldrsa.PublicKey{PublicKey: pub.PublicKey}
}

// Size returns the key size, in bits, of the public key.
func (pub *public) Size() int {
	return pub.PublicKey.Size()
}

// GetN returns the RSA public key modulus.
func (pub *public) GetN() *large.Int {
	return large.NewIntFromBigInt(pub.N)
}

// GetE returns the RSA public key exponent.
func (pub *public) GetE() int {
	return pub.E
}

// MarshalPem returns a PEM encoding of the public key.
func (pub *public) MarshalPem() []byte {
	// Note: we have to dig into the wrapper's .PrivateKey object
	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&pub.PublicKey),
	}
	pemBytes := pem.EncodeToMemory(block)
	return pemBytes[:len(pemBytes)-1] // Strip newline
}

// MarshalWire returns a marshaled version of the public key that contains
// everything needed to reconstruct it. Specifically, both the public exponent
// and the modulus.
//
// Notice: the size of the return will be 4 bytes longer than the key size.
// It can be found using PublicKey.GetMarshalWireLength.
func (pub *public) MarshalWire() []byte {
	buf := make([]byte, ELength)
	binary.BigEndian.PutUint32(buf, uint32(pub.GetE()))
	return append(buf, pub.PublicKey.N.Bytes()...)
}

// GetMarshalWireLength returns the length of a marshalled wire version of the
// public key returned from PublicKey.MarshalWire.
func (pub *public) GetMarshalWireLength() int {
	return pub.Size() + ELength
}
