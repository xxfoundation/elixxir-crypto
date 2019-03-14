package e2e

import (
	"encoding/binary"
	"gitlab.com/elixxir/primitives/id"
	"testing"
)

// Exit Criteria: Tests showing valid keys can be generated for all extant user pairs.
func TestDummyKeyGen_ValidKeys(t *testing.T) {

	user := id.NewUserFromUint(uint64(0), t)
	users := [1]id.User{*id.NewUserFromUint(uint64(0), t)}

	keys := KeyGen(*user, users[:], grp)

	print(keys)

}

// Helper function to generate users from slice of user ids
func generateUsers(ids []uint64) (users []id.User) {

	users = make([]id.User, len(ids))

	var result id.User
	for i, id := range ids {
		binary.BigEndian.PutUint64(result[:], id)
		users[i] = result
	}

	return users
}

// Test to ensure the number of keys equals the number of users to combine with
func TestDummyKeyGen_ValidNumKeys(t *testing.T) {

	currUser := generateUsers([]uint64{1})[0]

	userIds := []uint64{1,2,3,4,5,6}
	users := generateUsers(userIds)

	keys := KeyGen(currUser, users, grp)
	if len(keys) != len(users) {
		t.Errorf("Wrong number of keys generated")
	}

	userIds = []uint64{1,2,3,4,5,6,7,8,9,10}
	users = generateUsers(userIds)
	keys = KeyGen(currUser, users, grp)
	if len(keys) != len(users) {
		t.Errorf("Wrong number of keys generated")
	}

	userIds = []uint64{8,9,10}
	users = generateUsers(userIds)
	keys = KeyGen(currUser, users, grp)
	if len(keys) != len(users) {
		t.Errorf("Wrong number of keys generated")
	}
}

func TestDummyKeyGen_KeysSorted(t *testing.T) {

	// create init user list in various orders

	// send to KeyGen

	// assert output is all the same and same length

}
