////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package cmix

import (
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/xx_network/crypto/large"
	"gitlab.com/xx_network/primitives/id"
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
var primeLength = len(grp.GetPBytes())
var baseKey = grp.NewIntFromString("a906df88f30d6afbfa6165a50cc9e208d16b34e70b367068dc5d6bd6e155b2c3", 16)
var rid = id.Round(42)
var salt = []byte("fdecfa52a8ad1688dbfa7d16df74ebf27e535903c469cefc007ebbe1ee895064")
var expectStr = "5e2dea50eb3422571384debaea7fef4e97f8ece160ffc50ccd7ebfe6d4" +
	"f4ec56e4b756f95193b6b8dccf5d68a9abb5a8f0c5cec1a37f2b1ff531827c864f408a25" +
	"cd026540f7d32e419dcbe5d675c611bdbf544925fe1cdf579df0ecfcc58e152ac27c31b0" +
	"05b0d5cdfb46192c91f6db4c745ec1cb94747d566ac408f76a2951930f13f30226d9493c" +
	"0842e6d4d8349cb777e354eb75de8325f85c2c6eaf6cfc04b7dfd32167b963b8812f30df" +
	"ce95510212d872964bad9bd59d9673ad13461bbe023193b0708099e8804762e527bb3652" +
	"8dcce0af4f6fd0fa09cffaf220a4031e90ad9bacab3f57998415a1e178274da666e8946e" +
	"b81d88e71f12537f44cc78"

func makeBaseKeys(size int) []*cyclic.Int {
	keys := make([]*cyclic.Int, 0)

	for i := 0; i < size; i++ {
		keys = append(keys, baseKey)
	}

	return keys
}

// FIXME: commented out to work with go 1.16.4
// // Test that keyGen() produces the correct key.
// func TestKeyGen(t *testing.T) {
// 	key := grp.NewInt(1)
// 	keyGen(grp, salt, rid, baseKey, key)
//
// 	expected := grp.NewIntFromString(expectStr, 16)
//
// 	if key.Cmp(expected) != 0 {
// 		t.Errorf("keyGen() generated an incorrect key"+
// 			"\n\treceived: %v\n\texpected: %v",
// 			key.TextVerbose(16, 0),
// 			expected.TextVerbose(16, 0))
// 	}
// }
//
// // Test that NodeKeyGen() produces the correct key. This is the same test as
// // TestKeyGen() because NodeKeyGen() is a wrapper of keyGen().
// func TestNodeKeyGen(t *testing.T) {
// 	key := grp.NewInt(1)
// 	NodeKeyGen(grp, salt, rid, baseKey, key)
//
// 	expected := grp.NewIntFromString(expectStr, 16)
//
// 	if key.Cmp(expected) != 0 {
// 		t.Errorf("NodeKeyGen() generated an incorrect key"+
// 			"\n\treceived: %v\n\texpected: %v",
// 			key.TextVerbose(16, 0),
// 			expected.TextVerbose(16, 0))
// 	}
// }
//
// // Test that multiple baseKeys return a slice of same size with correct results
// func TestClientKeyGen(t *testing.T) {
// 	size := 10
// 	key := ClientKeyGen(grp, salt, rid, makeBaseKeys(size))
//
// 	expected := grp.NewInt(1)
// 	tmpKey := grp.NewInt(1)
//
// 	for i := 0; i < size; i++ {
// 		tmpKey = grp.NewIntFromString(expectStr, 16)
// 		keyGen(grp, salt, rid, baseKey, tmpKey)
// 		grp.Mul(tmpKey, expected, expected)
// 	}
// 	grp.Inverse(expected, expected)
//
// 	if key.Cmp(expected) != 0 {
// 		t.Errorf("ClientKeyGen() generated an incorrect key"+
// 			"\n\treceived: %v\n\texpected: %v",
// 			key.TextVerbose(10, 35),
// 			expected.TextVerbose(10, 35))
// 	}
// }
