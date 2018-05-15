package diffie_hellman

import (
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/privategrity/crypto/cyclic"
)

// CreateDHKeyPair is a function that receives the generator and prime and
// returns a Diffie-Hellman Key pair withing the group
func CreateDHKeyPair(group cyclic.Group) (*cyclic.Int, *cyclic.Int) {

	if !group.Prime.IsPrime() {
		jww.FATAL.Panicf("CreateDHKeyPair(): Passed number is not prime")
	}

	//256 bits
	size := 32
	k1, _ := cyclic.GenerateRandomKey(size)

	privateKey := cyclic.NewIntFromBytes(k1)

	publicKey := cyclic.NewInt(0)
	publicKey.Exp(group.G, privateKey, group.Prime)

	return privateKey, publicKey
}

// NewDHSessionKey takes the prime, the other party's public key and private key
// Function returns a valid session Key within the group
// v1.0 still does not include the CheckPublicKeyFeature
func CreateDHSessionKey(publicKey *cyclic.Int, privateKey *cyclic.Int, group cyclic.Group) (*cyclic.Int, error) {

	sessionKey := cyclic.NewInt(0)
	sessionKey.Exp(publicKey, privateKey, group.Prime)

	return sessionKey, nil
}

// CheckPublicKey uses the Legendre Symbol calculation to check if a specific public key is valid
// This function can return false positives, but never false negatives
// A valid public key will never trigger a negative response from this function
// Legendre Symbol = a^(p-1)/2 mod p
func CheckPublicKey(group cyclic.Group, publicKey *cyclic.Int) bool {

	//Definition of the bounds for the public key: 1 and (prime-1)
	//Cmp returns -1 if number is smaller, 0 if the same and 1 if bigger than.
	x := publicKey.Cmp(group.One)
	y := publicKey.Cmp(group.Psub1)

	// Public Key must be bigger than 1 and smaller than p-1
	if x != 1 || y != -1 {
		return false
	}

	z := cyclic.NewInt(0)
	z.Div(group.Psub1, cyclic.NewInt(2))

	symbol := cyclic.NewInt(0)
	symbol.Exp(publicKey, z, group.Prime)

	if symbol.Cmp(group.One) == 0 {
		return true
	} else {
		return false
	}
}
