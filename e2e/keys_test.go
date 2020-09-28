////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/xx_network/primitives/id"
	"testing"
)

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
	EXPECTED_KEY   = "2e0d10f4a3d34128b8c682cf700beed425ed3791a322597a34522" +
		"de04683b375827d088ec0b5081efd98f69d47b611fabb781acedfc37b8d51df5cd" +
		"69a63706d9787c9fc34710555128c8ac31125e4baec9ea3be3953b9ab97205a7a2" +
		"a34e293dc4741d30e45d1851d81fe92e0d881fd500e23f2fe2b94e690dd69b6ef8" +
		"d0bd4ae00f894278293cf1af0f14cb107355cbf639c9e671d085b1f723ef341721" +
		"24f41d8da3d8f81dd55e51e9597f3a319444ece2f6e960a46f653cd747c65f9084" +
		"2527c2993dd0620de7cc227b9b81c3e3bfad7844f2157ccb5ccb16504118c89bbd" +
		"c810a0dec3768ed0a29c1681b5cf14c956e095bdec668776e74b29fac8c9bb57f1" +
		"433519f521a6ce447ad04aac82d97db8be878ded25844e3b8d46b44ed39482ede4" +
		"33e95ef6979b2e403dfaf1aff7e67b442c4f519b24da619fc4f6052aeec3b7ed14" +
		"8936479a88ea0efdc0b5489e45b63f3c19e8b857ee89c1f6e804842d6b2bb1cc05" +
		"3afeb1672303d0a72e1352c9cf1fabc8851e4afdae5324fb10137d6356e7c7fbe2" +
		"5309134d19a3b67336d"
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
}
