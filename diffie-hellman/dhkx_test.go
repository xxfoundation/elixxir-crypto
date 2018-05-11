package diffie_hellman

import (
	"gitlab.com/privategrity/crypto/cyclic"
	"testing"
)

// TestDHKX tests both the CreateDHKeyPair & CreateDHSessionKey
// This function checks if values are within the expected group and if session keys between two parties match
func TestDHKX(t *testing.T) {

	tests := 3
	pass := 0

	g := cyclic.NewInt(2)

	primeString := "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
		"15728E5A8AACAA68FFFFFFFFFFFFFFFF"
	prime := cyclic.NewInt(0)
	prime.SetString(primeString, 16)

	// Creation of two different DH Key Pairs with valid parameters
	privKey, pubKey := CreateDHKeyPair(g, prime)
	privKey2, pubKey2 := CreateDHKeyPair(g, prime)

	// Check if Public Key is within the group
	if pubKey.Cmp(prime) != -1 {
		t.Errorf("TestNewDHKeyPair(): Public Key is bigger than the prime!")
	} else {
		pass++
	}

	//Creation of 2 DH Session Keys
	sessionKey1, _ := CreateDHSessionKey(pubKey, privKey2, prime)
	sessionKey2, _ := CreateDHSessionKey(pubKey2, privKey, prime)

	// Comparison of Two Session Keys (0 means they are equal)
	if sessionKey1.Cmp(sessionKey2) != 0 {
		t.Errorf("TestDHKX(): Error in CreateDHSessionKey() -> Session Keys do not match!")
	} else {
		pass++
	}

	// Check if Session Key is within the prime group
	if sessionKey1.Cmp(prime) != -1 {
		t.Errorf("TestNewDHKeyPair(): Session Key is bigger than the prime!")
	} else {
		pass++
	}

	println("TestDHKX():", pass, "out of", tests, "tests passed.")
}

// Catch calls recover to catch the panic thrown in the GenerateSharedKey() test functions
func Catch(fn string, t *testing.T) {
	if r := recover(); r != nil {
		println("Good news! Panic was caught!", fn, " Had to trigger recover in", r)
	} else {
		t.Errorf("No panic was caught and it was expected to!")
	}
}

// TestCreateDHKeyPair checks if panic is triggered when passing a number that is not a prime
func TestCreateDHKeyPair(t *testing.T) {

	g := cyclic.NewInt(2)

	defer Catch("TestCreateDHKeyPair():", t)
	CreateDHKeyPair(g, cyclic.NewInt(4))
}
