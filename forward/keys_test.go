package forward

import (
	"encoding/hex"
	"testing"
)

//TestExpandKey verifies if function rejects small keys & salts and if it correctly outputs a 256 byte value
func TestExpandKey(t *testing.T) {

	test := 3
	pass := 0

	key := []byte("a906df88f30d6afbfa6165a50cc9e208d16b34e70b367068dc5d6bd6e155b2c3")
	salt := []byte("fdecfa52a8ad1688dbfa7d16df84ebf27e535903c469cefc007ebbe1ee895064")

	x1, err := ExpandKey([]byte("key"), []byte("1"))
	x2, _ := ExpandKey(key, salt)

	if err != nil {
		pass++
	} else {
		t.Errorf("TestExpandKey(): Error in the Key Expansion. Keys size alert should have been triggered!")
	}

	if hex.EncodeToString(x1) != hex.EncodeToString(x2) {
		pass++
	} else {
		t.Errorf("TestExpandKey():Error in the Key Expansion. Keys should not be the same!")
	}

	if len(x2) != 256 {
		t.Errorf("TestExpandKey(): Key size is not the expected 256 bytes value!")
	} else {
		pass++
	}

	println("TestExpandKey():", pass, "out of", test, "tests passed")
}

//TestUpdateKey tests if function correctly rejects salts & keys that are less than 256 bits long
// This function also tests if the output key has the correct size.
func TestUpdateKey(t *testing.T) {

	test := 5
	pass := 0

	baseKey := []byte("key")
	salt := []byte("salt")

	baseKey2 := []byte("a906df88f30d6afbfa6165a50cc9e208d16b34e70b367068dc5d6bd6e155b2c3")
	salt2 := []byte("fdecfa52a8ad1688dbfa7d16df84ebf27e535903c469cefc007ebbe1ee895064")

	NextKey, e1 := UpdateKey(baseKey, salt)
	NextKey2, e2 := UpdateKey(baseKey2, salt2)

	if e1 != nil {
		pass++
	} else {
		t.Errorf("TestUpdateKey(): Error should have been triggered!")
	}

	if e2 != nil {
		t.Errorf("TestUpdateKey(): Error should not have been triggered!")
	} else {
		pass++
	}

	if NextKey != nil {
		t.Errorf("TestUpdateKey(): Error should have been triggered!")
	} else {
		pass++
	}

	if NextKey2 != nil {
		pass++
	} else {
		t.Errorf("TestUpdateKey(): Error should have been triggered!")
	}

	if len(NextKey2) != 256 {
		t.Errorf("TestUpdateKey(): Key size is not the expected 256 bytes value!")
	} else {
		pass++
	}

	println("TestUpdateKey():", pass, "out of", test, "tests passed.")
}
