////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package cmix

import (
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/large"
	"testing"
)

var base = 16

var pString = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
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

var gString = "5C7FF6B06F8F143FE8288433493E4769C4D988ACE5BE25A0E24809670716C613" +
	"D7B0CEE6932F8FAA7C44D2CB24523DA53FBE4F6EC3595892D1AA58C4328A06C4" +
	"6A15662E7EAA703A1DECF8BBB2D05DBE2EB956C142A338661D10461C0D135472" +
	"085057F3494309FFA73C611F78B32ADBB5740C361C9F35BE90997DB2014E2EF5" +
	"AA61782F52ABEB8BD6432C4DD097BC5423B285DAFB60DC364E8161F4A2A35ACA" +
	"3A10B1C4D203CC76A470A33AFDCBDD92959859ABD8B56E1725252D78EAC66E71" +
	"BA9AE3F1DD2487199874393CD4D832186800654760E1E34C09E4D155179F9EC0" +
	"DC4473F996BDCE6EED1CABED8B6F116F7AD9CF505DF0F998E34AB27514B0FFE7"

var qString = "2"

var p = large.NewIntFromString(pString, base)
var g = large.NewIntFromString(gString, base)

var grp = cyclic.NewGroup(p, g)

var baseKey = grp.NewIntFromString("a906df88f30d6afbfa6165a50cc9e208d16b34e70b367068dc5d6bd6e155b2c3", 16)
var salt = []byte("fdecfa52a8ad1688dbfa7d16df74ebf27e535903c469cefc007ebbe1ee895064")
var expectStr = "2e4c99e14e0b1cd18c08467c395a4d5c0eb594507595041a5cfa83eb2f57" +
	"91f3db46c933040d4c9862b91539fb8bc75e0b84ed07dd6a760dda6baec8c5f3f119eff0" +
	"0a0bdd6bc712c43e3f98d34cde6f6234191b1c68b9b2d9a80ad7652513caf0bae5fc3070" +
	"bd921c914a67d55005ce624c0140782cbe8ab55327e21ba0328379cfadda661d835be329" +
	"125fa237e9848af469b4b68cc922f994d404e3f8818f9c84ef9e6a6b2efbfdc5f24ec7cd" +
	"346775225b4abe84d202b479b91d19399ab216dc3f7961fcc499f4287323c2a96df0127a" +
	"b4f4ab64be76ca2906a49ad4ee3f0240f80a881177b9ed4a903dc5667473cec67ab4d52c" +
	"7f73f019311e6ccf9a75"

func makeBaseKeys(size int) []*cyclic.Int {
	keys := make([]*cyclic.Int, 0)

	for i := 0; i < size; i++ {
		keys = append(keys, baseKey)
	}

	return keys
}

// Test that keyGen() produces the correct key.
func TestKeyGen(t *testing.T) {
	key := grp.NewInt(1)
	keyGen(grp, salt, baseKey, key)

	expected := grp.NewIntFromString(expectStr, 16)

	if key.Cmp(expected) != 0 {
		t.Errorf("keyGen() generated an incorrect key"+
			"\n\treceived: %v\n\texpected: %v",
			key.TextVerbose(10, 35),
			expected.TextVerbose(10, 35))
	}
}

// Test that NodeKeyGen() produces the correct key. This is the same test as
// TestKeyGen() because NodeKeyGen() is a wrapper of keyGen().
func TestNodeKeyGen(t *testing.T) {
	key := grp.NewInt(1)
	NodeKeyGen(grp, salt, baseKey, key)

	expected := grp.NewIntFromString(expectStr, 16)

	if key.Cmp(expected) != 0 {
		t.Errorf("NodeKeyGen() generated an incorrect key"+
			"\n\treceived: %v\n\texpected: %v",
			key.TextVerbose(10, 35),
			expected.TextVerbose(10, 35))
	}
}

// Test that multiple baseKeys return a slice of same size with correct results
func TestClientKeyGen(t *testing.T) {
	size := 10
	key := ClientKeyGen(grp, salt, makeBaseKeys(size))

	expected := grp.NewInt(1)
	tmpKey := grp.NewInt(1)

	for i := 0; i < size; i++ {
		tmpKey = grp.NewIntFromString(expectStr, 16)
		keyGen(grp, salt, baseKey, tmpKey)
		grp.Mul(tmpKey, expected, expected)
	}
	grp.Inverse(expected, expected)

	if key.Cmp(expected) != 0 {
		t.Errorf("ClientKeyGen() generated an incorrect key"+
			"\n\treceived: %v\n\texpected: %v",
			key.TextVerbose(10, 35),
			expected.TextVerbose(10, 35))
	}
}
