////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package diffieHellman

import (
	"fmt"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/csprng"
	"gitlab.com/elixxir/crypto/cyclic"
)

// CreateDHKeyPair is a function that receives the generator and prime and
// returns a Diffie-Hellman Key pair withing the group
func CreateDHKeyPair(group *cyclic.Group) (*cyclic.Int, *cyclic.Int) {
	if !group.GetP().IsPrime() {
		jww.FATAL.Panicf("CreateDHKeyPair(): Passed number is not prime")
	}

	//256 bits
	size := 32

	csprig := csprng.NewSystemRNG()

	k1 := make([]byte, size)

	_, err := csprig.Read(k1)

	if err != nil {
		panic(fmt.Sprintf("Key RNG in Diffie Hellman Failed: %s", err.Error()))
	}

	privateKey := group.NewIntFromBytes(k1)

	publicKey := group.NewInt(0)
	group.Exp(group.GetGCyclic(), privateKey, publicKey)

	return privateKey, publicKey
}

// NewDHSessionKey takes the prime, the other party's public key and private key
// Function returns a valid session Key within the group
// v1.0 still does not include the CheckPublicKeyFeature
func CreateDHSessionKey(publicKey *cyclic.Int, privateKey *cyclic.Int,
	group *cyclic.Group) (*cyclic.Int, error) {
	sessionKey := group.NewInt(0)
	group.Exp(publicKey, privateKey, sessionKey)

	return sessionKey, nil
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

	//Cmp returns -1 if number is smaller, 0 if the same and 1 if bigger than.
	x := publicKey.Cmp(lowerBound)
	y := publicKey.Cmp(upperBound)

	// Public Key must be bigger than 1 and smaller than p-1
	if x != 1 || y != -1 {
		return false
	}

	symbol := group.NewInt(0)
	group.Exp(publicKey, group.GetPSub1FactorCyclic(), symbol)

	// Symbol must be equal to 1
	if symbol.Cmp(lowerBound) == 0 {
		return true
	} else {
		return false
	}
}
