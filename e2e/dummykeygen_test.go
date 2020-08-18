////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package e2e

import (
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/large"
	"gitlab.com/elixxir/primitives/id"
	"os"
	"testing"
)

var grp *cyclic.Group

// Build global group for tests to utilise
func TestMain(m *testing.M) {
	// Create group
	primeString := "E2EE983D031DC1DB6F1A7A67DF0E9A8E5561DB8E8D49413394C049B" +
		"7A8ACCEDC298708F121951D9CF920EC5D146727AA4AE535B0922C688B55B3DD2AE" +
		"DF6C01C94764DAB937935AA83BE36E67760713AB44A6337C20E7861575E745D31F" +
		"8B9E9AD8412118C62A3E2E29DF46B0864D0C951C394A5CBBDC6ADC718DD2A3E041" +
		"023DBB5AB23EBB4742DE9C1687B5B34FA48C3521632C4A530E8FFB1BC51DADDF45" +
		"3B0B2717C2BC6669ED76B4BDD5C9FF558E88F26E5785302BEDBCA23EAC5ACE9209" +
		"6EE8A60642FB61E8F3D24990B8CB12EE448EEF78E184C7242DD161C7738F32BF29" +
		"A841698978825B4111B4BC3E1E198455095958333D776D8B2BEEED3A1A1A221A6E" +
		"37E664A64B83981C46FFDDC1A45E3D5211AAF8BFBC072768C4F50D7D7803D2D4F2" +
		"78DE8014A47323631D7E064DE81C0C6BFA43EF0E6998860F1390B5D3FEACAF1696" +
		"015CB79C3F9C2D93D961120CD0E5F12CBB687EAB045241F96789C38E89D796138E" +
		"6319BE62E35D87B1048CA28BE389B575E994DCA755471584A09EC723742DC35873" +
		"847AEF49F66E43873"
	p := large.NewIntFromString(primeString, 16)
	g := large.NewInt(2)
	grp = cyclic.NewGroup(p, g)

	os.Exit(m.Run())
}

// Test to ensure the number of keys equals the number of users to combine with
func TestDummyKeyGen_ValidNumKeys(t *testing.T) {

	currUser := generateUsers([]uint64{12345}, t)[0]

	userIds := []uint64{1, 2, 3, 4, 5, 6}
	users := generateUsers(userIds, t)
	keys := KeyGen(currUser, users, grp)
	if len(keys) != len(users) {
		t.Errorf("Wrong number of keys generated")
	}

	userIds = []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	users = generateUsers(userIds, t)
	keys = KeyGen(currUser, users, grp)
	if len(keys) != len(users) {
		t.Errorf("Wrong number of keys generated")
	}

	userIds = []uint64{8, 9, 10}
	users = generateUsers(userIds, t)
	keys = KeyGen(currUser, users, grp)
	if len(keys) != len(users) {
		t.Errorf("Wrong number of keys generated")
	}
}

// Ensure keys generated from a list of user ids
// is deterministic and reproducible
func TestDummyKeyGen_KeysMatch(t *testing.T) {

	currUser := generateUsers([]uint64{12345}, t)[0]

	userIds := []uint64{1, 2, 3, 4, 5, 6}
	users := generateUsers(userIds, t)

	keys1 := KeyGen(currUser, users, grp)

	userIds = []uint64{6, 5, 4, 3, 2, 1}
	users = generateUsers(userIds, t)

	keys2 := KeyGen(currUser, users, grp)

	l := len(keys1)
	for i, v := range keys1 {
		if v.Cmp(keys2[l-i-1]) != 0 {
			t.Errorf("Key mismatch")
		}
	}

}

// Ensure that order doesn't matter when generating a hash from two user ids
func TestDummyKeyGen_CombinedHashCommutes(t *testing.T) {

	userA := generateUsers([]uint64{12345}, t)[0]

	userB := generateUsers([]uint64{5}, t)[0]

	res1 := combinedHash(userA, userB, grp)

	res2 := combinedHash(userB, userA, grp)

	if res1.Cmp(res2) != 0 {
		t.Errorf("Combined hash order should not matter")
	}
}

// Helper function to generate users from slice of user ids
func generateUsers(uids []uint64, t *testing.T) []*id.ID {

	users := make([]*id.ID, len(uids))

	for i, uid := range uids {
		users[i] = id.NewIdFromUInt(uid, id.User, t)
	}

	return users
}
