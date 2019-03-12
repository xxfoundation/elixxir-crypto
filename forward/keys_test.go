////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package forward

import (
	"crypto/sha256"
	"encoding/hex"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/hash"
	"testing"
)

var primeString = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
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

var p = cyclic.NewIntFromString(primeString, 16)
var min = cyclic.NewInt(2)
var max = cyclic.NewInt(0)
var seed = cyclic.NewInt(42)
var rng = cyclic.NewRandom(min, max.Mul(p, cyclic.NewInt(1000)))
var g = cyclic.NewInt(2)
var grp = cyclic.NewGroup(p, seed, g, rng)

//TestExpandKey verifies if function rejects small keys & salts and if it correctly outputs a 256 byte value
func TestExpandKey(t *testing.T) {
	test := 2
	pass := 0

	key := []byte("a906df88f30d6afbfa6165a50cc9e208d16b34e70b367068dc5d6bd6e155b2c3")

	b, _ := hash.NewCMixHash()
	x1 := ExpandKey(b, &grp, []byte("key"))
	b.Reset()
	x2 := ExpandKey(b, &grp, key)

	if len(x1) != 256 {
		t.Errorf("TestExpandKey(): Error with the resulting key size")
	} else {
		pass++
	}

	if hex.EncodeToString(x1) != hex.EncodeToString(x2) {
		pass++
	} else {
		t.Errorf("TestExpandKey():Error in the Key Expansion. Keys should not be the same!")
	}

	println("TestExpandKey():", pass, "out of", test, "tests passed")
}

//TestUpdateKey tests if function correctly rejects salts & keys that are less than 256 bits long
// This function also tests if the output key has the correct size.
func TestUpdateKey(t *testing.T) {
	test := 2
	pass := 0

	baseKey := []byte("a906df88f30d6afbfa6165a50cc9e208d16b34e70b367068dc5d6bd6e155b2c3")
	salt := []byte("fdecfa52a8ad1688dbfa7d16df74ebf27e535903c469cefc007ebbe1ee895064")

	b, _ := hash.NewCMixHash()
	h := sha256.New()
	NextKey := UpdateKey(&grp, baseKey, salt, b, h)

	if NextKey != nil {
		pass++
	} else {
		t.Errorf("TestUpdateKey(): Error should have been triggered!")
	}

	if len(NextKey) != 256 {
		t.Errorf("TestUpdateKey(): Key size is not the expected 256 bytes value!")
	} else {
		pass++
	}
	println("TestUpdateKey():", pass, "out of", test, "tests passed.")
}
