////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package e2e

/*
// Assuming DHKey in 2048bit group
const (
	TEST_DHKEY = "8da81b3784ff5fc3c3bd5a5a2cf94d5315dd56cd585ef9944306627e7ccd3c69" +
		"77fcf2db6ffe95e859136d07e24c7f9b25bf7aed37f7333152a6456c1babf107" +
		"c9bb2de486690fd5e4389690802f77bd68503ff9bd89d038daf0e899db3cc558" +
		"aec65a3cae8eff0af6e0f04fa0f798ff8b2ca6a7307ebfbbc2059e5e7ab552f3" +
		"c988063401b0cd23bb5587d538ccf17353e38972f36d382c58cddb9446abe464" +
		"57ffff98dc24dc323c1ea04b0e17c3608ba5ea254d7e9cd585445018ce0fb43c" +
		"4f7869a4450fbb8451d6b8e9a4509824988bce01d33688c3afdea173b5206f68" +
		"cdc392fed7267caef8398e817512ee46aedf6019b6d82a1d9040204d09873d78"
	TEST_USERID    = 42
	TEST_PARTNERID = 11
	EXPECTED_KEY   = "5d0bf414c2e1c15b4f3c47ed08f99ec69f67771bb1b1c41b8fa" +
		"df02c869bc6d7f75c347ed98893402f95e4b6d07c59ff88f594" +
		"2d0e1e639c1818a1cb5bc1e0fbfc8865f2aa4d11422ef16e65d" +
		"8715b4fdad60af1280ebfa4e2a4a77dafe1a159b4883aff68de" +
		"a7b66b476f49dc2947e3bed2c409c2bcb40443a6d7c5a058db3" +
		"4281da9af9bd1a4eee3afd330bb3e50d3d9d0df555dcabbeb21" +
		"18b4068240d8632f988a0edd8a5fa9e24887dd2f86ed47c7bc0" +
		"02d13d38659de86f54fe3f8b6200c2c932962e1a4c562c421a8" +
		"37908dc8a8378fd697cd896e6b3729a0cc9b5b3075e7d69a307" +
		"94cadb3366447242db03148d9ff94d3fb30628cf89cd893ece8" +
		"2a40a8e314e3ed4ff05337f64fd238484601fc1329feb2989a7" +
		"4452431c75ff8b2d031d47e941accde1bafb95d4f2373399a12" +
		"4dc59eca021465108c018bc73f5bc6e67c82088a02816069e65" +
		"30043754e7afecb815345f93e933c24bb523bf935debb10bb19" +
		"cecc53d7528c0382996544f737189737cbfa8ffd5848d0cac82" +
		"eb8f569e970d732c3869e7d23cd2cf31e"
)

type testFun func(a *cyclic.Group, b *cyclic.Int, c *id.ID, d uint) []*cyclic.Int

// Test for consistency with hardcoded values
func TestDeriveSingleKey(t *testing.T) {
	userID := id.NewIdFromUInt(TEST_USERID, id.User, t)
	key := grp.NewIntFromString(TEST_DHKEY, 16)
	data := append([]byte{}, key.Bytes()...)
	data = append(data, userID.Bytes()...)
	result := deriveSingleKey(sha256.New(), grp, data, 0)
	expected := grp.NewIntFromString(EXPECTED_KEY, 16)
	if result.Cmp(expected) != 0 {
		t.Errorf("Generated Key \n %v \n doesn't match expected \n %v",
			result.TextVerbose(16, 0), EXPECTED_KEY)
	}
}

// Test both functions with various arguments
func TestDeriveKeys_DeriveEmergencyKeys(t *testing.T) {
	userID := id.NewIdFromUInt(TEST_USERID, id.User, t)
	partnerID := id.NewIdFromUInt(TEST_PARTNERID, id.User, t)
	key := grp.NewIntFromString(TEST_DHKEY, 16)

	nkeys := []uint{10000, 0}
	total := func(a []uint) (s int) {
		for _, n := range a {
			s += int(n)
		}
		return s
	}(nkeys)

	ids := []*id.ID{userID, partnerID}
	fut := []testFun{DeriveKeys, DeriveEmergencyKeys}

	pass := 0
	tests := len(nkeys) * len(ids) * len(fut)

	expectedKeys := (tests / len(nkeys)) * (total)
	testmap := make(map[string]bool)
	var genKeys = []*cyclic.Int{}

	for _, n := range nkeys {
		for _, iditr := range ids {
			for _, f := range fut {
				genKeys = f(grp, key, iditr, n)

				// Check array of keys and if the size matches with requested
				if genKeys == nil {
					t.Errorf("Generated Array of Keys is nil")
				} else if uint(len(genKeys)) != n {
					t.Errorf("Requested %d keys but got %d instead", n, len(genKeys))
				} else {
					// Check each key
					for _, k := range genKeys {
						if k == nil {
							t.Errorf("One generated Key is nil")
						} else {
							testmap[hex.EncodeToString(k.Bytes())] = true
						}
					}
					pass++
				}
			}
		}
	}

	// Confirm all generated keys are different
	if len(testmap) != expectedKeys {
		t.Errorf("Expected %d different keys, but got %d", expectedKeys, len(testmap))
	}

	println("TestDeriveKeys_DeriveEmergencyKeys()", pass, "out of", tests, "tests passed.")
}

// Test both functions with same arguments to explicitly show they produce different keys
func TestDeriveKeys_DeriveEmergencyKeys_Differ(t *testing.T) {
	userID := id.NewIdFromUInt(TEST_USERID, id.User, t)
	key := grp.NewIntFromString(TEST_DHKEY, 16)
	nkeys := uint(100)
	fut := []testFun{DeriveKeys, DeriveEmergencyKeys}
	var genKeys = make([][]*cyclic.Int, len(fut))

	for i, f := range fut {
		genKeys[i] = f(grp, key, userID, nkeys)

		// Check array of keys and if the size matches with requested
		if genKeys[i] == nil {
			t.Errorf("Generated Array of Keys is nil")
		} else if uint(len(genKeys[i])) != nkeys {
			t.Errorf("Requested %d keys but got %d instead", nkeys, len(genKeys))
		}
	}

	// Directly compare each key
	for i := 0; i < int(nkeys); i++ {
		if genKeys[0][i].Cmp(genKeys[1][i]) == 0 {
			t.Errorf("Keys are the same when generated with different functions")
		}
	}
}*/
