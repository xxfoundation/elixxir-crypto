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

// Package diffieHellman implements a Diffie-Hellman key exchange. Includes creation of DH keypairs,
// DH session keys, and checking the validity of DH public keys
package diffieHellman

import (
	"fmt"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/xx_network/crypto/csprng"
	"io"
)

const DefaultPrivateKeyLengthBits = 256
const DefaultPrivateKeyLength = DefaultPrivateKeyLengthBits / 8

// Creates a private key of the passed length in bits in the given group using
// the passed csprng. The length of the key must be within the prime of the
// group. It is recommended to use the "DefaultPrivateKeyLength"
// for most use cases.
// key size must be divisible by 8
func GeneratePrivateKey(size int, group *cyclic.Group, source io.Reader) *cyclic.Int {

	k1, err := csprng.GenerateInGroup(group.GetPBytes(), size, source)

	if err != nil {
		panic(fmt.Sprintf("Failed to generate key: %s", err.Error()))
	}

	privateKey := group.NewIntFromBytes(k1)

	return privateKey
}

// Computes a public key for the given private key. The private key must be
// in the group passed
func GeneratePublicKey(myPrivateKey *cyclic.Int, group *cyclic.Group) *cyclic.Int {

	publicKey := group.NewInt(1)
	group.Exp(group.GetGCyclic(), myPrivateKey, publicKey)

	return publicKey
}

// CreateSessionKey takes the prime, the other party's public key and private key
// Function returns a valid session Key within the group
func GenerateSessionKey(myPrivateKey *cyclic.Int, theirPublicKey *cyclic.Int,
	group *cyclic.Group) *cyclic.Int {
	sessionKey := group.NewInt(1)
	group.Exp(theirPublicKey, myPrivateKey, sessionKey)

	return sessionKey
}

// CheckPublicKey uses the Legendre Symbol calculation to check if a specific public key is valid
// This function can return false positives, but never false negatives
// A valid public key will never trigger a negative response from this function
// Legendre Symbol = a^(p-1)/2 mod p
func CheckPublicKey(group *cyclic.Group, publicKey *cyclic.Int) bool {
	// Definition of the lower bound to 1
	lowerBound := group.NewInt(1)

	// Definition of the upper bound to p-1
	upperBound := group.GetPSub1Cyclic()

	// Cmp returns -1 if number is smaller, 0 if the same and 1 if bigger than.
	x := publicKey.Cmp(lowerBound)
	y := publicKey.Cmp(upperBound)

	// Public Key must be bigger than 1 and smaller than p-1
	if x != 1 || y != -1 {
		return false
	}

	symbol := group.NewInt(1)
	group.Exp(publicKey, group.GetPSub1FactorCyclic(), symbol)

	// Symbol must be equal to 1
	if symbol.Cmp(lowerBound) == 0 {
		return true
	} else {
		return false
	}
}
