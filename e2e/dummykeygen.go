package e2e

import (
	"bytes"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/elixxir/primitives/id"
)

func CombinedHash(ida *id.User, idb *id.User, grp cyclic.Group) *cyclic.Int {

	h, _ := hash.NewCMixHash()

	// Create combined key by appending the smaller slice
	var combKey []byte
	as := ida.Bytes()
	bs := idb.Bytes()
	if bytes.Compare(as, bs) >= 0 {
		combKey = append(ida.Bytes(), idb.Bytes()...)
	} else {
		combKey = append(idb.Bytes(), ida.Bytes()...)
	}

	expKey := hash.ExpandKey(h, &grp, combKey)

	return cyclic.NewIntFromBytes(expKey)

}

func KeyGen(currentUser id.User, users []id.User, grp cyclic.Group) []cyclic.Int {
	keys := make([]cyclic.Int, len(users))

	for i, user := range users {
		keys[i]  = *CombinedHash(&currentUser, &user, grp)
	}

	return keys
}

