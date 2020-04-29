////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package xx

import (
	"crypto/rsa"
	"gitlab.com/elixxir/crypto/csprng"
	"gitlab.com/elixxir/primitives/id"
	"math/rand"
	"testing"
)

func TestNewID(t *testing.T) {
	// use insecure seeded rng to reproduce key
	rng := rand.New(rand.NewSource(42))
	pk, err := rsa.GenerateKey(rng, 4096)
	if err != nil {
		t.Errorf(err.Error())
	}
	salt := make([]byte, 32)
	for i := 0; i < 32; i++ {
		salt[i] = byte(i)
	}
	nid, err := NewID(pk.PublicKey, salt, 1)
	if err != nil {
		t.Errorf(err.Error())
	}
	if len(nid) != id.ArrIDLen {
		t.Errorf("wrong ID length: %d", len(nid))
	}
	if nid[len(nid)-1] != 1 {
		t.Errorf("wrong type: %d", nid[len(nid)-1])
	}
	expected := []byte{122, 15, 124, 177, 225, 209,
		252, 65, 148, 66, 145, 157, 128, 160,
		77, 82, 129, 2, 97, 227, 5, 2, 126,
		78, 136, 122, 238, 179, 156, 28, 115,
		198, 1}
	for i := 0; i < len(expected); i++ {
		if expected[i] != nid[i] {
			t.Errorf("Output did not match expected at %d: %d != %d",
				i, nid[i], expected[i])
		}
	}

	// Send bad type
	_, err = NewID(pk.PublicKey, salt, 7)
	if err == nil {
		t.Errorf("Should have failed with bad type!")
	}

	// Send back salt
	_, err = NewID(pk.PublicKey, salt[0:4], 7)
	if err == nil {
		t.Errorf("Should have failed with bad salt!")
	}

	// Check ideal usage with our RNG
	rng2 := csprng.NewSystemRNG()
	pk, err = rsa.GenerateKey(rng2, 4096)
	if err != nil {
		t.Errorf(err.Error())
	}
	salt, err = csprng.Generate(32, rng)
	if err != nil {
		t.Errorf(err.Error())
	}
	nid, err = NewID(pk.PublicKey, salt, id.Gateway)
	if err != nil {
		t.Errorf(err.Error())
	}
}
