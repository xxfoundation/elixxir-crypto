////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package xx

import (
	"gitlab.com/elixxir/crypto/csprng"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"gitlab.com/xx_network/primitives/id"
	"math/rand"
	"reflect"
	"testing"
)

func TestNewID(t *testing.T) {
	// use insecure seeded rng to reproduce key
	rng := rand.New(rand.NewSource(42))
	rng.Seed(42)
	pk, err := rsa.GenerateKey(rng, 4096)
	if err != nil {
		t.Errorf(err.Error())
	}
	salt := make([]byte, 32)
	for i := 0; i < 32; i++ {
		salt[i] = byte(i)
	}
	nid, err := NewID(pk.GetPublic(), salt, 1)
	if err != nil {
		t.Errorf(err.Error())
	}
	if len(nid) != id.ArrIDLen {
		t.Errorf("wrong ID length: %d", len(nid))
	}
	if nid[len(nid)-1] != 1 {
		t.Errorf("wrong type: %d", nid[len(nid)-1])
	}

	// rsa key generation has two possible outputs to stop use of its
	// deterministic nature so we check both possible outputs and use
	// its deterministic nature
	expectedID1 := id.NewIdFromBytes([]byte{122, 15, 124, 177, 225, 209, 252, 65,
		148, 66, 145, 157, 128, 160, 77, 82, 129, 2, 97, 227, 5, 2, 126, 78, 136,
		122, 238, 179, 156, 28, 115, 198, 1}, t)

	expectedID2 := id.NewIdFromBytes([]byte{73, 68, 157, 125, 57, 194, 165, 132,
		64, 84, 100, 41, 93, 237, 227, 161, 114, 140, 215, 66, 146, 233, 151, 33,
		24, 119, 98, 166, 104, 13, 252, 226, 1}, t)

	if !reflect.DeepEqual(expectedID1, nid) && !reflect.DeepEqual(expectedID2, nid) {
		t.Errorf("Recieved ID did not match expected: "+
			"Expected: %s or %s, Recieved: %s", expectedID1, expectedID2, nid)
	}

	// Send bad type
	_, err = NewID(pk.GetPublic(), salt, 7)
	if err == nil {
		t.Errorf("Should have failed with bad type!")
	}

	// Send back salt
	_, err = NewID(pk.GetPublic(), salt[0:4], 7)
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
	nid, err = NewID(pk.GetPublic(), salt, id.Gateway)
	if err != nil {
		t.Errorf(err.Error())
	}
}
