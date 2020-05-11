////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// Package rsa includes wrappers to sign and verify the signatures of messages
// with the PKCS#1 RSASSA-PSS signature algorithm:
//
//   https://tools.ietf.org/html/rfc3447#page-29
//
// We use this because of the "tighter" security proof and regression to full
// domain hashing in cases where good RNG is unavailable.
//
// The primary reason for wrapping is to interface with the large Int api
// used by cMix.
package rsa

import (
	"crypto"
	gorsa "crypto/rsa"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/elixxir/crypto/large"
	"io"
)

//Key length used in the system in bits
var DefaultRSABitLen = 4096

// Options is a direct wrapper for PSSOptions
type Options struct {
	gorsa.PSSOptions
}

// PrivateKey is identical to the rsa private key, with additional
// big int accessors functions.
type PrivateKey struct {
	gorsa.PrivateKey
}

// GetD returns the private exponent of the RSA Private Key as
// a large.Int
func (p *PrivateKey) GetD() *large.Int {
	return large.NewIntFromBigInt(p.D)
}

// GetPrimes returns the prime factors of N, which has >= 2 elements
func (p *PrivateKey) GetPrimes() []*large.Int {
	primes := make([]*large.Int, len(p.Primes))
	for i := 0; i < len(p.Primes); i++ {
		primes[i] = large.NewIntFromBigInt(p.Primes[i])
	}
	return primes
}

// GetDp returns D mod (P - 1), or nil if unavailable
func (p *PrivateKey) GetDp() *large.Int {
	if p.Precomputed.Dp == nil {
		return nil
	}
	return large.NewIntFromBigInt(p.Precomputed.Dp)
}

// GetDq returns D mod (Q - 1), or nil if unavailable
func (p *PrivateKey) GetDq() *large.Int {
	if p.Precomputed.Dq == nil {
		return nil
	}
	return large.NewIntFromBigInt(p.Precomputed.Dq)
}

// GetPublicKey returns the public key in *rsa.PublicKey format
func (p *PrivateKey) GetPublic() *PublicKey {
	return &PublicKey{p.PublicKey}
}

/* NOTE: This is included for completeness, but since we don't use
         the multi configuration, the CRTValues struct inside the PrivateKey
         should always be empty for our purposes. Leaving this present and
         commented to document that fact.

// CRTValue holds Exp, Coeff, R as large.Int's
type CRTValue struct {
	Exp   *large.Int // D mod (prime-1).
        Coeff *large.Int // R·Coeff ≡ 1 mod Prime.
        R     *large.Int // product of primes prior to this (inc p and q).
}

// GetCRTValues returns large.Int versions of all precomputed chinese
// remainder theorum values
func (priv *PrivateKey) GetCRTValues() []*CRTValue {
	if priv.Precomputed.CRTValues == nil {
		return nil
	}
	crtValues := make([]*CRTValue, len(priv.Precomputed.CRTValues))
	for i := 0; i < len(priv.Precomputed.CRTValues); i++ {
		cur := priv.Precomputed.CRTValues[i]
		crtValues[i] = &CRTValue{
			Exp: large.NewIntFromBigInt(cur.Exp),
			Coeff: large.NewIntFromBigInt(cur.Coeff),
			R: large.NewIntFromBigInt(cur.R),
		}
	}
	return crtValues
}
*/

// PublicKey is identical to the rsa public key, with additonal
// big int access functions.
type PublicKey struct {
	gorsa.PublicKey
}

// Public returns the public key corresponding to priv.
func (p *PrivateKey) Public() crypto.PublicKey {
	return &PublicKey{p.PublicKey}
}

// GetN returns the RSA Public Key modulus
func (p *PublicKey) GetN() *large.Int {
	return large.NewIntFromBigInt(p.N)
}

// GenerateKey generates an RSA keypair of the given bit size using the
// random source random (for example, crypto/rand.Reader).
func GenerateKey(random io.Reader, bits int) (*PrivateKey, error) {
	pk, err := gorsa.GenerateMultiPrimeKey(random, 2, bits)
	return &PrivateKey{*pk}, err
}

// NewDefaultOptions returns signing options that set the salt length equal
// to the lenght of the hash and uses the default cMix Hash algorithm.
func NewDefaultOptions() *Options {
	return &Options{
		gorsa.PSSOptions{
			SaltLength: gorsa.PSSSaltLengthEqualsHash,
			Hash:       hash.CMixHash,
		},
	}
}

// Sign uses RSASSA-PSS to calculate the signature of hashed. Note
// that hashed must be the result of hashing the input message using the
// given hash function. The opts argument may be nil, in which case
// the default cMix hash and salt length == size of the hash are used.
func Sign(rand io.Reader, priv *PrivateKey, hash crypto.Hash, hashed []byte,
	opts *Options) ([]byte, error) {
	if opts == nil {
		opts = NewDefaultOptions()
		opts.Hash = hash
	}

	return gorsa.SignPSS(rand, &priv.PrivateKey, hash, hashed,
		&opts.PSSOptions)
}

// Verify verifies a PSS signature. hashed is the result of hashing
// the input message using the given hash function and sig is the
// signature. A valid signature is indicated by returning a nil
// error. The opts argument may be nil, in which case the default cMix hash
// and salt length == size of the hash are used.
func Verify(pub *PublicKey, hash crypto.Hash, hashed []byte, sig []byte,
	opts *Options) error {
	if opts == nil {
		opts = NewDefaultOptions()
		opts.Hash = hash
	}

	return gorsa.VerifyPSS(&pub.PublicKey, hash, hashed, sig,
		&opts.PSSOptions)
}

// IsValidSignature approximates whether the signature looks valid
// by comparing the length of the signature to the length of the public key
func IsValidSignature(pubKey *PublicKey, signature []byte) bool {
	if pubKey == nil {
		return false
	}
	return len(signature) == pubKey.Size()
}
