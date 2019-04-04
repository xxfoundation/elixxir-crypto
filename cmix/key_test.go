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
	"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
	"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
	"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
	"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
	"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
	"43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7" +
	"88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA" +
	"2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6" +
	"287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED" +
	"1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9" +
	"93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199" +
	"FFFFFFFFFFFFFFFF"
var prime = large.NewIntFromString(primeString, 16)
var grp = cyclic.NewGroup(prime, large.NewInt(4), large.NewInt(3))
var baseKey = grp.NewIntFromString("a906df88f30d6afbfa6165a50cc9e208d16b34e70b367068dc5d6bd6e155b2c3", 16)
var salt = []byte("fdecfa52a8ad1688dbfa7d16df74ebf27e535903c469cefc007ebbe1ee895064")
var expectStr = "2e4c99e14e0b1cd18c08467c395a4d5c0eb594507595041a5cfa83eb2f5791f3" +
	"db46c933040d4c9862b91539fb8bc75e0b84ed07dd6a760dda6baec8c5f3f119" +
	"eff00a0bdd6bc712c43e3f98d34cde6f6234191b1c68b9b2d9a80ad7652513ca" +
	"f0bae5fc3070bd921c914a67d55005ce624c0140782cbe8ab55327e21ba03283" +
	"79cfadda661d835be329125fa237e9848af469b4b68cc922f994d404e3f8818f" +
	"9c84ef9e6a6b2efbfdc5f24ec7cd346775225b4abe84d202b479b91d19399ab2" +
	"16dc3f7961fcc499f4287323c2a96df0127ab4f4ab64be76ca2906a49ad4ee3f" +
	"0240f80a881177b9ed4a903dc5667473cec67ab4d52c7f73f019311e6ccf9a75" +
	"d6d34710e6e8609e964c1c1e7769dde406535d4a82c2e965a5f40cce5bef66ef" +
	"f8d6eb7715851aaff93c2eb8cac0b7d8ca14d341ccae3d09bff69154957332ce" +
	"65e34ba28e72ee50fb8a6a6c255d1fcf3abe334320f2a452ec9ce92e5202a624" +
	"ce2fdafc1c6ecbf2bb45fe5f7a1cc5cd4f8e44cea96bf0e78aa63240166cc12a" +
	"5d3a1469263c49a7648a5b53062b79ab43f93788da0aeeb2972c2f49da0a5101" +
	"b6b8c927d3f133f80420eaa50817932d853ac73505ff9f46632c7303ce234419" +
	"027a52385d2ae763c69ed1ce41a72f0c682aeef563050b7eeef4e0c1117c7f1f" +
	"54ee909454cdece58148e759a88f1dbd45bf2e2479b8f983ac0eb3f85b8b0fed"

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
