package rsa

import (
	"crypto"
	gorsa "crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"gitlab.com/xx_network/crypto/large"
	oldrsa "gitlab.com/xx_network/crypto/signature/rsa"
	"hash"
	"io"
)

type private struct {
	gorsa.PrivateKey
}

// SignPSS calculates the signature of digest using PSS.
//
// hashed must be the result of hashing the input message using the given hash
// function. The opts argument may be nil, in which case sensible defaults are
// used. If opts.Hash is set, it overrides hash.
//
// This function uses the standard crypto/rsa implementation.
func (priv *private) SignPSS(rand io.Reader, hash crypto.Hash, hashed []byte,
	opts *PSSOptions) ([]byte, error) {
	if opts == nil {
		opts = NewDefaultPSSOptions()
		opts.Hash = hash
	}

	return gorsa.SignPSS(rand, &priv.PrivateKey, hash, hashed, &opts.PSSOptions)
}

// SignPKCS1v15 calculates the signature of hashed using RSASSA-PKCS1-V1_5-SIGN
// from RSA PKCS #1 v1.5.  Note that hashed must be the result of hashing the
// input message using the given hash function. If hash is zero, hashed is
// signed directly. This isn't advisable except for interoperability.
//
// If random is not nil, then RSA blinding will be used to avoid timing
// side-channel attacks.
//
// This function is deterministic. Thus, if the set of possible messages is
// small, an attacker may be able to build a map from messages to signatures and
// identify the signed messages. As ever, signatures provide authenticity, not
// confidentiality.
func (priv *private) SignPKCS1v15(
	random io.Reader, hash crypto.Hash, hashed []byte) ([]byte, error) {
	return gorsa.SignPKCS1v15(random, &priv.PrivateKey, hash, hashed)
}

// DecryptOAEP decrypts ciphertext using RSA-OAEP.
//
// OAEP is parameterised by a hash function that is used as a random oracle.
// Encryption and decryption of a given message must use the same hash function
// and sha256.New() is a reasonable choice.
//
// The random parameter, if not nil, is used to blind the private-key operation
// and avoid timing side-channel attacks. Blinding is purely internal to this
// function – the random data need not match that used when encrypting.
//
// The label parameter must match the value given when encrypting. See
// [PublicKey.EncryptOAEP] for details.
func (priv *private) DecryptOAEP(hash hash.Hash, random io.Reader,
	ciphertext []byte, label []byte) ([]byte, error) {
	return gorsa.DecryptOAEP(hash, random, &priv.PrivateKey, ciphertext, label)
}

// DecryptPKCS1v15 decrypts a plaintext using RSA and the padding scheme from
// PKCS #1 v1.5. If random != nil, it uses RSA blinding to avoid timing
// side-channel attacks.
//
// Note that whether this function returns an error or not discloses secret
// information. If an attacker can cause this function to run repeatedly and
// learn whether each instance returned an error then they can decrypt and forge
// signatures as if they had the private key. See
// [PrivateKey.DecryptPKCS1v15SessionKey] for a way of solving this problem.
func (priv *private) DecryptPKCS1v15(
	random io.Reader, ciphertext []byte) ([]byte, error) {
	return gorsa.DecryptPKCS1v15(random, &priv.PrivateKey, ciphertext)
}

// DecryptPKCS1v15SessionKey decrypts a session key using RSA and the padding
// scheme from PKCS #1 v1.5. If random != nil, it uses RSA blinding to avoid
// timing side-channel attacks. It returns an error if the ciphertext is the
// wrong length or if the ciphertext is greater than the public modulus.
// Otherwise, no error is returned. If the padding is valid, the resulting
// plaintext message is copied into key. Otherwise, key is unchanged. These
// alternatives occur in constant time. It is intended that the user of this
// function generate a random session key beforehand and continue the protocol
// with the resulting value. This will remove any possibility that an attacker
// can learn any information about the plaintext.
// See “Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption
// Standard PKCS #1”, Daniel Bleichenbacher, Advances in Cryptology
// (Crypto '98).
//
// Note that if the session key is too small then it may be possible for an
// attacker to brute-force it. If they can do that then they can learn whether
// a random value was used (because it'll be different for the same ciphertext)
// and thus whether the padding was correct. This defeats the point of this
// function. Using at least a 16-byte key will protect against this attack.
func (priv *private) DecryptPKCS1v15SessionKey(
	random io.Reader, ciphertext []byte, key []byte) error {
	return gorsa.DecryptPKCS1v15SessionKey(
		random, &priv.PrivateKey, ciphertext, key)
}

// Public returns the public key in [rsa.PublicKey] format.
func (priv *private) Public() PublicKey {
	return &public{
		PublicKey: priv.PublicKey,
	}
}

// GetGoRSA returns the private key in the standard Go [crypto/rsa] format.
func (priv *private) GetGoRSA() *gorsa.PrivateKey {
	return &priv.PrivateKey
}

// GetOldRSA returns the private key in the old wrapper format for RSA that was
// used in xx project.
//
// Deprecated: Only use for compatibility during the transition.
func (priv *private) GetOldRSA() *oldrsa.PrivateKey {
	return &oldrsa.PrivateKey{PrivateKey: priv.PrivateKey}
}

// Size returns the key size, in bits, of the private key.
func (priv *private) Size() int {
	return priv.PublicKey.Size()
}

// GetD returns the private exponent of the RSA private key as a [large.Int].
func (priv *private) GetD() *large.Int {
	return large.NewIntFromBigInt(priv.D)
}

// GetPrimes returns the list of prime factors of N, which has >= 2 elements.
func (priv *private) GetPrimes() []*large.Int {
	primes := make([]*large.Int, len(priv.Primes))
	for i := range primes {
		primes[i] = large.NewIntFromBigInt(priv.Primes[i])
	}
	return primes
}

// GetDp returns D mod (P - 1), or nil if unavailable.
func (priv *private) GetDp() *large.Int {
	if priv.Precomputed.Dp == nil {
		return nil
	}
	return large.NewIntFromBigInt(priv.Precomputed.Dp)
}

// GetDq returns D mod (Q - 1), or nil if unavailable.
func (priv *private) GetDq() *large.Int {
	if priv.Precomputed.Dq == nil {
		return nil
	}
	return large.NewIntFromBigInt(priv.Precomputed.Dq)
}

// MarshalPem returns a PEM encoding of the private key.
func (priv *private) MarshalPem() []byte {
	// Note: we have to dig into the wrapper's .PrivateKey object
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(&priv.PrivateKey),
	}
	pemBytes := pem.EncodeToMemory(block)
	return pemBytes[:len(pemBytes)-1] // Strip newline
}
