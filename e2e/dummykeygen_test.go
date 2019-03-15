////////////////////////////////////////////////////////////////////////////////
// Copyright © 2019 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package e2e

import (
	"encoding/binary"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/primitives/id"
	"testing"
)

// Test to ensure the number of keys equals the number of users to combine with
func TestDummyKeyGen_ValidNumKeys(t *testing.T) {

	grp := generateGroup()
	currUser := generateUsers([]uint64{12345})[0]

	userIds := []uint64{1, 2, 3, 4, 5, 6}
	users := generateUsers(userIds)

	keys := KeyGen(currUser, users, grp)
	if len(keys) != len(users) {
		t.Errorf("Wrong number of keys generated")
	}

	userIds = []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	users = generateUsers(userIds)
	keys = KeyGen(currUser, users, grp)
	if len(keys) != len(users) {
		t.Errorf("Wrong number of keys generated")
	}

	userIds = []uint64{8, 9, 10}
	users = generateUsers(userIds)
	keys = KeyGen(currUser, users, grp)
	if len(keys) != len(users) {
		t.Errorf("Wrong number of keys generated")
	}
}

// Ensure keys generated from a list of user ids
// is deterministic and reproducible
func TestDummyKeyGen_KeysMatch(t *testing.T) {

	grp := generateGroup()
	currUser := generateUsers([]uint64{12345})[0]

	userIds := []uint64{1, 2, 3, 4, 5, 6}
	users := generateUsers(userIds)

	keys1 := KeyGen(currUser, users, grp)

	userIds = []uint64{6, 5, 4, 3, 2, 1}
	users = generateUsers(userIds)

	keys2 := KeyGen(currUser, users, grp)

	l := len(keys1)
	for i, v := range keys1 {
		if v.Cmp(&keys2[l-i-1]) != 0 {
			t.Errorf("Key mismatch")
		}
	}

}

// Ensure that order doesn't matter when generating a hash from two user ids
func TestDummyKeyGen_CombinedHashCommutes(t *testing.T) {

	grp := generateGroup()
	userA := generateUsers([]uint64{12345})[0]

	userB := generateUsers([]uint64{5})[0]

	res1 := combinedHash(&userA, &userB, grp)

	res2 := combinedHash(&userB, &userA, grp)

	if res1.Cmp(res2) != 0 {
		t.Errorf("Combined hash order should not matter")
	}
}

// Helper function to generate users from slice of user ids
func generateUsers(uids []uint64) (users []id.User) {

	users = make([]id.User, len(uids))

	var result id.User
	for i, uid := range uids {
		binary.BigEndian.PutUint64(result[:], uid)
		users[i] = result
	}

	return users
}

// Generate a group for testing
func generateGroup() cyclic.Group {

	primeString := "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
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
	p := cyclic.NewIntFromString(primeString, 16)
	min := cyclic.NewInt(2)
	max := cyclic.NewInt(0)
	max.Mul(p, cyclic.NewInt(1000))
	seed := cyclic.NewInt(42)
	rng := cyclic.NewRandom(min, max)
	g := cyclic.NewInt(2)
	grp = cyclic.NewGroup(p, seed, g, rng)

	return grp
}
