////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package diffieHellman

import (
	"encoding/hex"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/large"
	"testing"
)

// TestDHKX tests both the CreateDHKeyPair & CreateDHSessionKey
// This function checks if values are within the expected group and if session keys between two parties match
func TestDHKX(t *testing.T) {

	tests := 3
	pass := 0

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
	p := large.NewInt(1)
	p.SetString(primeString, 16)
	g := large.NewInt(2)
	grp := cyclic.NewGroup(p, g)

	// Creation of two different DH Key Pairs with valid parameters
	privKey, pubKey := CreateDHKeyPair(grp)
	privKey2, pubKey2 := CreateDHKeyPair(grp)

	//Creation of 2 DH Session Keys
	sessionKey1, _ := CreateDHSessionKey(pubKey, privKey2, grp)
	sessionKey2, _ := CreateDHSessionKey(pubKey2, privKey, grp)

	// Comparison of Two Session Keys (0 means they are equal)
	if sessionKey1.Cmp(sessionKey2) != 0 {
		t.Errorf("TestDHKX(): Error in CreateDHSessionKey() -> Session Keys do not match!")
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

	p := large.NewInt(4)
	g := large.NewInt(2)
	grp := cyclic.NewGroup(p, g)

	defer Catch("TestCreateDHKeyPair():", t)
	CreateDHKeyPair(grp)
}

func TestCheckPublicKey(t *testing.T) {

	tests := 3
	pass := 0

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
	p := large.NewInt(1)
	p.SetString(primeString, 16)
	g := large.NewInt(2)
	grp := cyclic.NewGroup(p, g)

	// Creation of a DH Key Pair with valid parameters
	_, pubKey := CreateDHKeyPair(grp)

	// Random 2048 bit number that is not a quadratic residue
	randomNum := "27a0ed88dd37d9d9c041bd31500e239ac050b618502a64e7f703dba20390" +
		"36638ca17c7bca05973b9ab5057bc535bebe6b98afee010785a32ae06184dcfe12123" +
		"5ea901d154d317480f381ff1fc49867d22d3c8f1f9e83e6d19f7554401fc32148b3d0" +
		"40c57c7d7cc08445776bd8ffc0d62016bf82708985c97b873d0f81a87072d6bfbbbb0" +
		"1e31679386641720c444c00a64720ffe3649d2b1fdf458acf65d0e695d6a293c34c70" +
		"e84d5e5a66d710475b6baea78df56e0c5ee735d496c1e3bc7f5fa95b4cd1b1bd849f9" +
		"487411805e7c9a1503735ba3d7d71ffb8f51e8530abb335e9c315e56677d30a4f7144" +
		"0a34a6954938d29fd24a72aae3d4a0c2873ed4"

	a, _ := hex.DecodeString(randomNum)
	x := grp.NewIntFromBytes(a)

	rightSymbol := CheckPublicKey(grp, pubKey)
	fakeSymbol := CheckPublicKey(grp, grp.NewInt(1))
	falseSymbol := CheckPublicKey(grp, x)

	if rightSymbol {
		pass++
	} else {
		t.Errorf("TestCheckPublicKey(): Public Key is supposed to be valid!")
	}

	if fakeSymbol {
		t.Errorf("TestCheckPublicKey(): 1 should not be valid input!")
	} else {
		pass++
	}

	if falseSymbol {
		t.Errorf("TestCheckPublicKey(): Random value should not be valid!")
	} else {
		pass++
	}

	println("TestCheckPublicKey():", pass, "out of", tests, "tests passed.")
}

/*
// TestDHNodeKeys tests if the hardcoded keys are valid
func TestDHNodeKeys(t *testing.T) {

	tests := 3
	pass := 0

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
	p := large.NewInt(1)
	p.SetString(primeString, 16)
	g := large.NewInt(2)
	q := large.NewInt(3)
	grp := cyclic.NewGroup(p, g, q)
	testGroup := &grp

	// This is a map key(string) -> value (hex string)
	// To convert the contents to byte, one should do: res, _ := hex.DecodeString(nodeDHKeys["key"])
	nodeDHPrivateKeys := map[string]string{
		"1": "4676d728cf9515f474170042f7ea2da582900bcbf46e921b7a5a9139e36c94ab",
		"2": "9b9e9ba8826594edba543a08cff2805b56c618fecce7a186ada654d9a7a49ba9",
		"3": "137f66dc73ad0a2fafc2892fcd75fa578d1dda9a17268f5cd9fc778d85027ba4",
	}

	nodeDHPublicKeys := map[string]string{
		"1": "610867349dd0abad45c94a728fff49ffc0187723599c25c09805b14d43f6fc2d" +
			"de24bda8a38997ee11656bbf73c27098b51672fb212759474309edac7e877c38fcc5300cdaa0" +
			"6080154a140f80724e82f55f6388cb101bb4bd4c68930fb2493185508bda03608503dfbed434" +
			"632993df4ff4cbecc11891d5df1c3699b042bbd027d385f253ca7299869acc4792586f5c2d37" +
			"850afcbda08a8fe467d86729c30922a7983727bdf71bf0c9eed541e686e8b1a1ae1ca3f26aee" +
			"d42d881f28835e1b68cd89cbb35c5ad03f5fe4b6bd2fbaffdb284ac34ae65ecba4375701dfc9" +
			"a5d7cccf0fa1715b83502f638d076875ead5c7feac64095b1967cf9b89e6ac295f56",

		"2": "4dd10b87778ae0969e6c1fe1af002ec78f2ff676b8ab5f6ebf3e4b4228e78609" +
			"4d22f4c43cda66888b5d6b32c4cd44c3db33bc74078a0363a4dfe6f6d72da5ab312e7da3658" +
			"b31f1488f8eb5aaa002f471309cd8e2ca05ad10be3d2204b5c68e1bc46e3554737f295d739b" +
			"caa5f3316847fcdae513150d1f84a69b8ef92fc0bb540ef1bc90b6100170ac0bd3f2c6c9863" +
			"532c0d4f302dae33bb8c8f8b8d9fce1264a5e60ac2beaf3f0d415cfd68aeca3822e6ce3d5e7" +
			"e3b3ee477e272767cdd69eb6268cd696b79826256e25b7e5a3bc79dcd1f86f843b4d45d63e0" +
			"4ea078f5ddf4a22dc43503660387a94d60020e05d1e7f1e9c032cad58f2d7408755f49942",

		"3": "fa2f3be8b4d5f748ed8332193db18045b781acfe165e2a8a6924d6fc514f29d6" +
			"cdf49b917b3b67985294c31990f9e5f402e0ff471a4eee44a7910a42a89d11cd832043327ac" +
			"62c3bf9e55ecce5ca5b5d53d0d442b94c86797a30fefc6692627f756bc96c50d131355dec50" +
			"3af5df8b113f280fc24ff2591b6c062b009312345432f8c201694379e04909cedd2ee5b41b7" +
			"a5158ef5804679859f6fdf5a4be7defaaa4cdc0b5b66fc98cd85d19b9e53f79d513a9c0654a" +
			"438f2bdee2b22022eda1cc80930b65ac381ca519afa6646df357ca223aa63ffbadd3bc6476e" +
			"b88b482129d1167c7787662abf0a5bf434e934039e681092916a12d7be295482718f748af",
	}

	pk1, _ := hex.DecodeString(nodeDHPublicKeys["publicKey1"])
	pk2, _ := hex.DecodeString(nodeDHPublicKeys["publicKey2"])
	pk3, _ := hex.DecodeString(nodeDHPublicKeys["publicKey3"])

	sk1, _ := hex.DecodeString(nodeDHPrivateKeys["1"])
	sk2, _ := hex.DecodeString(nodeDHPrivateKeys["2"])
	sk3, _ := hex.DecodeString(nodeDHPrivateKeys["3"])

	// Keys between Node 1 & 2
	k12, _ := CreateDHSessionKey(grp.NewIntFromBytes(pk2), grp.NewIntFromBytes(sk1), testGroup)
	k21, _ := CreateDHSessionKey(grp.NewIntFromBytes(pk1), grp.NewIntFromBytes(sk2), testGroup)

	// Keys between Node 1 & 3
	k13, _ := CreateDHSessionKey(grp.NewIntFromBytes(pk1), grp.NewIntFromBytes(sk3), testGroup)
	k31, _ := CreateDHSessionKey(grp.NewIntFromBytes(pk3), grp.NewIntFromBytes(sk1), testGroup)

	// Keys between Node 2 & 3
	k23, _ := CreateDHSessionKey(grp.NewIntFromBytes(pk2), grp.NewIntFromBytes(sk3), testGroup)
	k32, _ := CreateDHSessionKey(grp.NewIntFromBytes(pk3), grp.NewIntFromBytes(sk2), testGroup)

	if k12.Cmp(k21) != 0 {
		t.Errorf("Keys between Node 1 & 2 do not match!")
	} else {
		pass++
	}

	if k13.Cmp(k31) != 0 {
		t.Errorf("Keys between Node 1 & 3 do not match!")
	} else {
		pass++
	}

	if k23.Cmp(k32) != 0 {
		t.Errorf("Keys between Node 2 & 3 do not match!")
	} else {
		pass++
	}

	println("TestDHNodeKeys():", pass, "out of", tests, "tests passed.")
}*/

func BenchmarkCreateDHSessionKey(b *testing.B) {
	b.StopTimer()
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
	p := large.NewInt(1)
	p.SetString(primeString, 16)
	g := large.NewInt(2)
	grp := cyclic.NewGroup(p, g)

	pubkeys := make([]*cyclic.Int, b.N)
	privkeys := make([]*cyclic.Int, b.N)

	for i := 0; i < b.N; i++ {

		// Creation of two different DH Key Pairs with valid parameters
		_, pubKey := CreateDHKeyPair(grp)
		privKey, _ := CreateDHKeyPair(grp)

		pubkeys[i] = pubKey
		privkeys[i] = privKey
	}

	b.StartTimer()
	for i := 0; i < b.N; i++ {

		CreateDHSessionKey(pubkeys[i], privkeys[i], grp)
	}

}
