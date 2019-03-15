////////////////////////////////////////////////////////////////////////////////
// Copyright © 2019 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package e2e

import (
	"encoding/binary"
	"gitlab.com/elixxir/primitives/id"
	"testing"
)

// Test to ensure the number of keys equals the number of users to combine with
func TestDummyKeyGen_ValidNumKeys(t *testing.T) {

	currUser := generateUsers([]uint64{12345})[0]

	userIds := []uint64{1, 2, 3, 4, 5, 6}
	users := generateUsers(userIds)

	keys := *KeyGen(&currUser, &users, &grp)
	if len(keys) != len(users) {
		t.Errorf("Wrong number of keys generated")
	}

	userIds = []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	users = generateUsers(userIds)
	keys = *KeyGen(&currUser, &users, &grp)
	if len(keys) != len(users) {
		t.Errorf("Wrong number of keys generated")
	}

	userIds = []uint64{8, 9, 10}
	users = generateUsers(userIds)
	keys = *KeyGen(&currUser, &users, &grp)
	if len(keys) != len(users) {
		t.Errorf("Wrong number of keys generated")
	}
}

// Ensure keys generated from a list of user ids
// is deterministic and reproducible
func TestDummyKeyGen_KeysMatch(t *testing.T) {

	currUser := generateUsers([]uint64{12345})[0]

	userIds := []uint64{1, 2, 3, 4, 5, 6}
	users := generateUsers(userIds)

	keys1 := *KeyGen(&currUser, &users, &grp)

	userIds = []uint64{6, 5, 4, 3, 2, 1}
	users = generateUsers(userIds)

	keys2 := *KeyGen(&currUser, &users, &grp)

	l := len(keys1)
	for i, v := range keys1 {
		if v.Cmp(&keys2[l-i-1]) != 0 {
			t.Errorf("Key mismatch")
		}
	}

}

// Ensure that order doesn't matter when generating a hash from two user ids
func TestDummyKeyGen_CombinedHashCommutes(t *testing.T) {

	userA := generateUsers([]uint64{12345})[0]

	userB := generateUsers([]uint64{5})[0]

	res1 := combinedHash(&userA, &userB, &grp)

	res2 := combinedHash(&userB, &userA, &grp)

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
