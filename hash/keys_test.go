/* Copyright 2020 xx network SEZC

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.

*/

package hash

import (
	"crypto/sha512"
	"encoding/hex"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/xx_network/crypto/large"
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

var p = large.NewIntFromString(primeString, 16)
var g = large.NewInt(2)
var grp = cyclic.NewGroup(p, g)

//TestExpandKey verifies ExpandKey with two different hashes
func TestExpandKey(t *testing.T) {
	test := 4
	pass := 0

	key := []byte("a906df88f30d6afbfa6165a50cc9e208d16b34e70b367068dc5d6bd6e155b2c3")

	b, _ := NewCMixHash()
	x1 := ExpandKey(b, grp, []byte("key"), grp.NewInt(1))
	b.Reset()
	x2 := ExpandKey(b, grp, key, grp.NewInt(1))

	if x1.BitLen()/8 != 256 {
		t.Errorf("TestExpandKey(): Error with the resulting key size")
	} else {
		pass++
	}

	if hex.EncodeToString(x1.Bytes()) != hex.EncodeToString(x2.Bytes()) {
		pass++
	} else {
		t.Errorf("TestExpandKey():Error in the Key Expansion. Keys should not be the same!")
	}

	h := sha512.New()
	x1 = ExpandKey(h, grp, []byte("key"), grp.NewInt(1))
	h.Reset()
	x2 = ExpandKey(h, grp, key, grp.NewInt(1))

	if x1.BitLen()/8 != 255 {
		t.Errorf("TestExpandKey(): Error with the resulting key size."+
			"Expected %v, Received: %v", 256, x1.BitLen()/8)
	} else {
		pass++
	}

	if hex.EncodeToString(x1.Bytes()) != hex.EncodeToString(x2.Bytes()) {
		pass++
	} else {
		t.Errorf("TestExpandKey():Error in the Key Expansion. Keys should not be the same!")
	}

	println("TestExpandKey():", pass, "out of", test, "tests passed")
}
