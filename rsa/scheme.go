////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

// Package rsa implements a wrapper on Go's [crypto/rsa] into a more sane object
// driven approach, while adding PEM and wire marshaling and unmarshalling
// formats as well as a Multicast OAEP feature, which encrypts with the private
// key and encrypts with the public key. Sensible defaults as well as printed
// warning when key sizes go too small have been added as well.
package rsa

import (
	gorsa "crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"io"
	"math/big"
)

// Memoization of the scheme object.
var s Scheme = &scheme{}

const (
	// softMinRSABitLen is the recommended minimum RSA key length allowed in
	// production. Use of any bit length smaller than this will result in a
	// warning log print.
	softMinRSABitLen = 3072

	// smallestPubkeyForUnmarshal is the smallest public key that the system can
	// unmarshal. This is ONLY for edge checking, and not a security
	// endorsement.
	smallestPubkeyForUnmarshal      = 64
	smallestPubkeyForUnmarshalBytes = smallestPubkeyForUnmarshal / 8

	// softMinRSABitLenWarn is a print to log on using too RSA keys that are too
	// small.
	softMinRSABitLenWarn = "CAUTION! RSA bit length %d is smaller than the " +
		"recommended minimum of %d bits. This is insecure; do not use in " +
		"production!"
)

// ErrTooShortToUnmarshal is returned when attempting to unmarshal a public key
// from wire format that is too short.
var ErrTooShortToUnmarshal = errors.New(
	"cannot unmarshal public key, it is too short")

// GetScheme returns the scheme that can be used for key marshaling and
// unmarshalling.
func GetScheme() Scheme {
	return s
}

type scheme struct{}

// Convert accepts a gorsa.PrivateKey and returns a PrivateKey interface
func (*scheme) Convert(key *gorsa.PrivateKey) PrivateKey {
	return &private{*key}
}

// GenerateDefault generates an RSA keypair of the library default bit size
// using the random source random (for example, crypto/rand.Reader).
func (s *scheme) GenerateDefault(random io.Reader) (PrivateKey, error) {
	return s.Generate(random, defaultRSABitLen)
}

// UnmarshalPrivateKeyPEM unmarshalls the private key from a PEM format. It will
// refuse to unmarshal a key smaller than 64 bits—this is not an endorsement of
// that key size.
//
// This function will print an error to the log if they key size is less than
// 3072 bits.
func (*scheme) UnmarshalPrivateKeyPEM(pemBytes []byte) (PrivateKey, error) {
	block, rest := pem.Decode(pemBytes)

	// Handles if structured as a PEM in a PEM
	if block == nil {
		block, _ = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("could not decode PEM")
		}
	}

	var key interface{}
	var err error

	// Decodes the PEM depending on type
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, errors.Errorf("could not decode key from PEM: %+v", err)
	}

	keyRSA, success := key.(*gorsa.PrivateKey)
	if !success {
		return nil, errors.New("decoded key is not an RSA key")
	}

	// Do edge checks: check if the keying material has a size issue
	if bits := keyRSA.Size() * 8; bits < softMinRSABitLen {
		jww.WARN.Printf(softMinRSABitLenWarn, bits, softMinRSABitLen)
	}

	return makePrivateKey(*keyRSA)
}

// UnmarshalPublicKeyPEM unmarshalls the public key from a PEM file. It will
// refuse to unmarshal a key smaller than 64 bits—this is not an endorsement of
// that key size.
//
// This function will print an error to the log if they key size is less than
// 3072 bits.
func (*scheme) UnmarshalPublicKeyPEM(pemBytes []byte) (PublicKey, error) {
	block, rest := pem.Decode(pemBytes)
	for block != nil && block.Type != "RSA PUBLIC KEY" {
		block, rest = pem.Decode(rest)
	}
	if block == nil {
		return nil, errors.New("No RSA PUBLIC KEY block in PEM file")
	}

	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// check if the keying material has a size issue
	if bits := key.Size() * 8; bits < softMinRSABitLen {
		jww.WARN.Printf(softMinRSABitLenWarn, bits, softMinRSABitLen)
	}

	return &public{*key}, nil
}

// UnmarshalPublicKeyWire unmarshalls the public key from a compact wire format.
//
// This function will return an error if the passed in byte slice is too small.
// It is expecting a minimum of 64-bit public key with a 32-bit public exponent,
// or a minimum length of 12 bytes.
//
// This acceptance criteria is not an endorsement of keys of those sizes being
// secure.
//
// Returns ErrTooShortToUnmarshal when the data is too short.
func (*scheme) UnmarshalPublicKeyWire(b []byte) (PublicKey, error) {
	// Do edge checks
	if len(b)+ELength < smallestPubkeyForUnmarshalBytes {
		return nil, ErrTooShortToUnmarshal
	}
	if bits := len(b) * 8; bits < softMinRSABitLen {
		jww.WARN.Printf(softMinRSABitLenWarn, bits, softMinRSABitLen)
	}

	// Unmarshal
	p := &public{}
	p.E = int(binary.BigEndian.Uint32(b[:ELength]))
	p.N = new(big.Int)
	p.N.SetBytes(b[ELength:])

	return p, nil
}

// GetDefaultKeySize returns the default key size, in bits, that the scheme will
// generate.
func (*scheme) GetDefaultKeySize() int {
	return defaultRSABitLen
}

// GetSoftMinKeySize returns the minimum key size, in bits, that the scheme will
// allow to be generated without printing an error to the log.
func (*scheme) GetSoftMinKeySize() int {
	return softMinRSABitLen
}

// GetMarshalWireLength returns the length of a Marshal Wire for a given key
// size, in bytes.
func (*scheme) GetMarshalWireLength(sizeBytes int) int {
	return sizeBytes + ELength
}
