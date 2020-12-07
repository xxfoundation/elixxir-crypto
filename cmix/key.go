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

// Package cmix derives new keys within the cyclic group from salts and a base key.
// It also is used for managing keys and salts for communication between clients
package cmix

import (
	"crypto/sha256"
	"crypto/sha512"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/hash"
)

// ClientKeyGen generate encryption key for clients.
func ClientKeyGen(grp *cyclic.Group, salt []byte, baseKeys []*cyclic.Int) *cyclic.Int {
	output := grp.NewInt(1)
	tmpKey := grp.NewInt(1)

	// Multiply all the generated keys together as they are generated.
	for _, baseKey := range baseKeys {
		keyGen(grp, salt, baseKey, tmpKey)
		grp.Mul(tmpKey, output, output)
	}

	grp.Inverse(output, output)

	return output
}

// NodeKeyGen generates encryption key for nodes.
func NodeKeyGen(grp *cyclic.Group, salt []byte, baseKey, output *cyclic.Int) {
	keyGen(grp, salt, baseKey, output)
}

// keyGen combines the salt with the baseKey to generate a new key inside the group.
func keyGen(grp *cyclic.Group, salt []byte, baseKey, output *cyclic.Int) *cyclic.Int {
	h1, _ := hash.NewCMixHash()
	h2 := sha256.New()

	a := baseKey.Bytes()

	// Blake2b Hash of the result of previous stage (base key + salt)
	h1.Reset()
	h1.Write(a)
	h1.Write(salt)
	x := h1.Sum(nil)

	// Different Hash (SHA256) of the previous result to add entropy
	h2.Reset()
	h2.Write(x)
	y := h2.Sum(nil)

	// Expand Key using SHA512
	k := hash.ExpandKey(sha512.New(), grp, y, output)
	return k
}
