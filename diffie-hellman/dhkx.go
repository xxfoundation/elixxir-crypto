package diffie_hellman

import (
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/privategrity/crypto/cyclic"
)

// CreateDHKeyPair is a function that receives the generator and prime and
// returns a Diffie-Hellman Key pair withing the group
func CreateDHKeyPair(g, p *cyclic.Int) (*cyclic.Int, *cyclic.Int) {

	if !p.IsPrime() {
		jww.FATAL.Panicf("CreateDHKeyPair(): Passed number is not prime")
	}

	//256 bits
	size := 32
	k1, _ := cyclic.GenerateRandomKey(size)

	privateKey := cyclic.NewIntFromBytes(k1)

	publicKey := cyclic.NewInt(0)
	publicKey.Exp(g, privateKey, p)

	return privateKey, publicKey
}

// NewDHSessionKey takes the prime, the other party's public key and private key
// Function returns a valid session Key within the group
// v1.0 still does not include the CheckPublicKeyFeature
func CreateDHSessionKey(publicKey *cyclic.Int, privateKey, p *cyclic.Int) (*cyclic.Int, error) {

	sessionKey := cyclic.NewInt(0)
	sessionKey.Exp(publicKey, privateKey, p)

	return sessionKey, nil
}
