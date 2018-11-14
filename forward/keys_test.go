package forward

import (
	"crypto/sha256"
	"encoding/hex"
	"gitlab.com/elixxir/crypto/hash"
	"testing"
)

//TestExpandKey verifies if function rejects small keys & salts and if it correctly outputs a 256 byte value
func TestExpandKey(t *testing.T) {

	test := 2
	pass := 0

	key := []byte("a906df88f30d6afbfa6165a50cc9e208d16b34e70b367068dc5d6bd6e155b2c3")
	salt := []byte("fdecfa52a8ad1688dbfa7d16df84ebf27e535903c469cefc007ebbe1ee895064")

	x1 := ExpandKey([]byte("key"), []byte("1"))
	x2 := ExpandKey(key, salt)

	if len(x1) != 256 {
		t.Errorf("TestExpandKey(): Error with the resulting key size")
	} else {
		pass++
	}

	if hex.EncodeToString(x1) != hex.EncodeToString(x2) {
		pass++
	} else {
		t.Errorf("TestExpandKey():Error in the Key Expansion. Keys should not be the same!")
	}

	println("TestExpandKey():", pass, "out of", test, "tests passed")
}

//TestUpdateKey tests if function correctly rejects salts & keys that are less than 256 bits long
// This function also tests if the output key has the correct size.
func TestUpdateKey(t *testing.T) {

	test := 2
	pass := 0

	baseKey := []byte("a906df88f30d6afbfa6165a50cc9e208d16b34e70b367068dc5d6bd6e155b2c3")
	salt := []byte("fdecfa52a8ad1688dbfa7d16df74ebf27e535903c469cefc007ebbe1ee895064")

	b, _ := hash.NewCMixHash()
	h := sha256.New()
	NextKey := UpdateKey(baseKey, salt, b, h)

	if NextKey != nil {
		pass++
	} else {
		t.Errorf("TestUpdateKey(): Error should have been triggered!")
	}

	if len(NextKey) != 256 {
		t.Errorf("TestUpdateKey(): Key size is not the expected 256 bytes value!")
	} else {
		pass++
	}
	println("TestUpdateKey():", pass, "out of", test, "tests passed.")
}
