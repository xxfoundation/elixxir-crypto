////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package hash

import (
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/xx_network/crypto/large"
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

var p = large.NewIntFromString(primeString, 16)
var g = large.NewInt(2)
var grp = cyclic.NewGroup(p, g)

// FIXME: commented out to work with go 1.16.4
// //TestExpandKey verifies ExpandKey with two different hashes
// func TestExpandKey(t *testing.T) {
// 	test := 4
// 	pass := 0
//
// 	key := []byte("a906df88f30d6afbfa6165a50cc9e208d16b34e70b367068dc5d6bd6e155b2c3")
//
// 	b, _ := NewCMixHash()
// 	x1 := ExpandKey(b, grp, []byte("key"), grp.NewInt(1))
// 	b.Reset()
// 	x2 := ExpandKey(b, grp, key, grp.NewInt(1))
//
// 	if x1.BitLen()/8 != 256 {
// 		t.Errorf("TestExpandKey(): Error with the resulting key size")
// 	} else {
// 		pass++
// 	}
//
// 	if hex.EncodeToString(x1.Bytes()) != hex.EncodeToString(x2.Bytes()) {
// 		pass++
// 	} else {
// 		t.Errorf("TestExpandKey():Error in the Key Expansion. Keys should not be the same!")
// 	}
//
// 	h := sha512.New()
// 	x1 = ExpandKey(h, grp, []byte("key"), grp.NewInt(1))
// 	h.Reset()
// 	x2 = ExpandKey(h, grp, key, grp.NewInt(1))
//
// 	if x1.BitLen()/8 != 255 {
// 		t.Errorf("TestExpandKey(): Error with the resulting key size."+
// 			"Expected %v, Received: %v", 256, x1.BitLen()/8)
// 	} else {
// 		pass++
// 	}
//
// 	if hex.EncodeToString(x1.Bytes()) != hex.EncodeToString(x2.Bytes()) {
// 		pass++
// 	} else {
// 		t.Errorf("TestExpandKey():Error in the Key Expansion. Keys should not be the same!")
// 	}
//
// 	println("TestExpandKey():", pass, "out of", test, "tests passed")
// }
