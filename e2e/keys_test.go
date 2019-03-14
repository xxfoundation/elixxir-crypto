package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/primitives/id"
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
	EXPECTED_KEY   = "e80f2642f97925105606e0e31d83051159192affa61a3d42901eb46deea78eb6" +
		"222885219dcd1e8b58d38df7652a8e98018663da60c5a69b5376b136de600a70" +
		"199b8b08573528a184f25d1caddb0be7aa9355942a7b21d6c82fefd129559cb9" +
		"3d4c9ef01197038870df04f233dc6185a60b2e38ff2decd181d63bff2e63f8a1" +
		"6b69a4263497d68a10b33557c9fd109df1ade76b7138516e77f6d6ea5043f371" +
		"4ef4d02d715f11511ec1cca1cdd3e2eac3e8b6cf431880e6cd28e1882aad94bb" +
		"15529b2726164f3c13c8459a66c98d6d272373766d3f287f3fba17c74183b2df" +
		"9d5d91c662a8ef9aa5e01a9da32897c1ca30437e17e1fe3b05ed58a3dfee5a2a"
)

// Test for consistency with hardcoded values
func TestDeriveSingleKey(t *testing.T) {
	userID := id.NewUserFromUint(TEST_USERID, t)
	partnerID := id.NewUserFromUint(TEST_PARTNERID, t)
	key := cyclic.NewIntFromString(TEST_DHKEY, 16)
	data := append([]byte{}, key.Bytes()...)
	data = append(data, userID.Bytes()...)
	data = append(data, partnerID.Bytes()...)
	result := deriveSingleKey(sha256.New(), &grp, data, 0)
	expected := cyclic.NewIntFromString(EXPECTED_KEY, 16)
	actual := cyclic.NewIntFromBytes(result)
	if actual.Cmp(expected) != 0 {
		t.Errorf("Generated Key %v doesn't match expected %v", actual.Text(16), EXPECTED_KEY)
	}
}

// Test both functions with same arguments
func TestDeriveKeys_DeriveReKeys(t *testing.T) {
	userID := id.NewUserFromUint(TEST_USERID, t)
	partnerID := id.NewUserFromUint(TEST_PARTNERID, t)
	key := cyclic.NewIntFromString(TEST_DHKEY, 16)
	n_keys := uint(1000)

	type testFun func(a *cyclic.Group, b *cyclic.Int, c, d *id.User, e uint) []*cyclic.Int
	fut := []testFun{DeriveKeys, DeriveReKeys}

	var genKeys = []*cyclic.Int{}
	for _, f := range fut {
		genKeys = f(&grp, key, userID, partnerID, n_keys)

		// Check array of keys and if the size matches with requested
		if genKeys == nil {
			t.Errorf("Generated Array of Keys is nil")
		} else if uint(len(genKeys)) != n_keys {
			t.Errorf("Requested %d keys but got %d instead", n_keys, len(genKeys))
		}

		testmap := make(map[string]bool)
		// Check each key
		for _, k := range genKeys {
			if k == nil {
				t.Errorf("One generated Key is nil")
			} else if !grp.Inside(k) {
				t.Errorf("Generated key is not inside the group")
			}
			testmap[hex.EncodeToString(k.Bytes())] = true
		}

		if uint(len(testmap)) < n_keys {
			t.Errorf("At least two Keys out of %d have the same value", n_keys)
		}
	}
}
