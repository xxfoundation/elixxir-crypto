//package e2e
//
//import (
//	"gitlab.com/elixxir/primitives/id"
//	"testing"
//)
//
//func TestDummyKeyGen_ValidKeys(t *testing.T) {
//
//	user := id.NewUserFromUint(uint64(0), t)
//	users := [1]id.User{*id.NewUserFromUint(uint64(0), t)}
//	// ([]byte, error)
//	keys, err := KeyGen(user, users)
//	if err != nil {
//		t.Errorf("Failed to generate base key pairs")
//	}
//	print(users)
//	print(user)
//	UserHash(user)
//
//	// keyPairs, err := KeyGen(user, users) where keyPairs are a tuple of cyclic.Int?
//
//}
//
//func TestDummyKeyGen_ValidNumKeys(t *testing.T) {
//	// check if len(users) == len(keys)
//}
//
//func TestDummyKeyGen_KeysSorted(t *testing.T) {
//	// do stuff
//
//	// loop and check i<=i+1<=i+2
//}
//
