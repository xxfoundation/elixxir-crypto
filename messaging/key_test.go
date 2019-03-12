////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package messaging

import (
	"gitlab.com/elixxir/crypto/cyclic"
	"testing"
)

var primeStrng = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
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
var prime = cyclic.NewIntFromString(primeStrng, 16)
var rng = cyclic.NewRandom(cyclic.NewInt(0),
	cyclic.NewIntFromString(primeStrng, 16))
var grp = cyclic.NewGroup(prime, cyclic.NewInt(5), cyclic.NewInt(4),
	rng)
var baseKey = cyclic.NewIntFromString("a906df88f30d6afbfa6165a50cc9e208d16b34e70b367068dc5d6bd6e155b2c3", 16)
var salt = []byte("fdecfa52a8ad1688dbfa7d16df74ebf27e535903c469cefc007ebbe1ee895064")
var expectStr = "2e4c99e14e0b1cd18c08467c395a4d5c0eb594507595041a5cfa83eb2f5791f3" +
	"db46c933040d4c9862b91539fb8bc75e0b84ed07dd6a760dda6baec8c5f3f119" +
	"eff00a0bdd6bc712c43e3f98d34cde6f6234191b1c68b9b2d9a80ad7652513ca" +
	"f0bae5fc3070bd921c914a67d55005ce624c0140782cbe8ab55327e21ba03283" +
	"79cfadda661d835be329125fa237e9848af469b4b68cc922f994d404e3f8818f" +
	"9c84ef9e6a6b2efbfdc5f24ec7cd346775225b4abe84d202b479b91d19399ab2" +
	"16dc3f7961fcc499f4287323c2a96df0127ab4f4ab64be76ca2906a49ad4ee3f" +
	"0240f80a881177b9ed4a903dc5667473cec67ab4d52c7f73f019311e6ccf9a75"

// Test for functionality of NewDecryptionKey using pre-canned values
func TestNewDecryptionKey(t *testing.T) {
	k := NewDecryptionKey(salt, baseKey, &grp)
	expected := cyclic.NewIntFromString(expectStr, 16)

	if k == nil {
		t.Errorf("Error should have been triggered!")
	}

	if k.Cmp(expected) != 0 {
		t.Errorf("Expected: %s, Got: %s", expected.Text(16), k.TextVerbose(16, 0))
	}
}

// Test for functionality of NewEncryptionKey using pre-canned values
func TestNewEncryptionKey(t *testing.T) {
	k := NewEncryptionKey(salt, baseKey, &grp)
	expected := cyclic.NewIntFromString(expectStr, 16)
	grp.Inverse(expected, expected)

	if k == nil {
		t.Errorf("Error should have been triggered!")
	}

	if k.Cmp(expected) != 0 {
		t.Errorf("Expected: %s, Got: %s", expected.Text(16), k.TextVerbose(16, 0))
	}
}

func makebaseKeys(size int) []*cyclic.Int {
	keys := make([]*cyclic.Int, 0)
	for i := 0; i < size; i++ {
		keys = append(keys, baseKey)
	}
	return keys
}

// Test that multiple baseKeys return a slice of same size with correct results
func TestNewDecryptionKeys(t *testing.T) {
	keys := NewDecryptionKeys(salt, makebaseKeys(10), &grp)
	expected := cyclic.NewIntFromString(expectStr, 16)
	if len(keys) != 10 {
		t.Errorf("Bad length: expected 10, got %d", len(keys))
	}
	for i := range keys {
		if keys[i].Cmp(expected) != 0 {
			t.Errorf("Generated key incorrect!")
		}
	}
}

// Test that an empty base key returns an empty result
func TestNewDecryptionKeysEmpty(t *testing.T) {
	keys := NewDecryptionKeys(salt, nil, &grp)
	if len(keys) != 0 {
		t.Errorf("Bad length: expected 0, got %d", len(keys))
	}
}

// Test that multiple baseKeys return a slice of same size with correct results
func TestNewEncryptionKeys(t *testing.T) {
	keys := NewEncryptionKeys(salt, makebaseKeys(10), &grp)
	expected := cyclic.NewIntFromString(expectStr, 16)
	grp.Inverse(expected, expected)
	if len(keys) != 10 {
		t.Errorf("Bad length: expected 10, got %d", len(keys))
	}
	for i := range keys {
		if keys[i].Cmp(expected) != 0 {
			t.Errorf("Generated key incorrect!")
		}
	}
}

// Test that an empty base key returns an empty result
func TestNewEncryptionKeysEmpty(t *testing.T) {
	keys := NewEncryptionKeys(salt, nil, &grp)
	if len(keys) != 0 {
		t.Errorf("Bad length: expected 0, got %d", len(keys))
	}
}
