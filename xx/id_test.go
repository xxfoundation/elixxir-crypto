////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package xx

import (
	"crypto/rsa"
	"gitlab.com/elixxir/crypto/csprng"
	"math/rand"
	"testing"
)

func TestIntToBytes(t *testing.T) {
	x := IntToBytes(1)
	if byte(1) != x[7] {
		t.Errorf("Int ToBytes: %d != %v", 1, x)
	}

	x = IntToBytes(-1)
	for i := 0; i < 8; i++ {
		if x[i] != 0xFF {
			t.Errorf("IntToBytes: %d != %v", -1, x)
		}
	}

	x = IntToBytes(65535)
	for i := 0; i < 8; i++ {
		if (i > 6 && x[i] != 0xFF) &&
			(i <= 6 && x[i] != 0) {
			t.Errorf("IntToBytes: %d != %v", -1, x)
		}
	}
}

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
	id, err := NewID(pk.PublicKey, salt, 1)
	if err != nil {
		t.Errorf(err.Error())
	}
	if len(id) != IdLen {
		t.Errorf("wrong ID length: %d", len(id))
	}
	if id[len(id)-1] != 1 {
		t.Errorf("wrong type: %d", id[len(id)-1])
	}
	expected := []byte{122, 15, 124, 177, 225, 209,
		252, 65, 148, 66, 145, 157, 128, 160,
		77, 82, 129, 2, 97, 227, 5, 2, 126,
		78, 136, 122, 238, 179, 156, 28, 115,
		198, 1}
	for i := 0; i < len(expected); i++ {
		if expected[i] != id[i] {
			t.Errorf("Output did not match expected at %d: %d != %d",
				i, id[i], expected[i])
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
	id, err = NewID(pk.PublicKey, salt, IDTypeGateway)
	if err != nil {
		t.Errorf(err.Error())
	}
}
