package fingerprint

import (
	"bytes"
	"gitlab.com/xx_network/primitives/id"
	"testing"
)

// Test IdentityFP properties
func TestIdentityFP(t *testing.T) {
	message1 := []byte("I'm an encrypted message!")
	message2 := []byte("I'm an encrypted message?")
	user1 := id.NewIdFromString("zezima", id.User, t)
	user2 := id.NewIdFromString("zez1ma", id.User, t)

	// Check that two fingerprints created from the same data are identical
	fp1, err := IdentityFP(message1, user1)
	if err != nil {
		t.Errorf("Failed to create identity fingerprint 1: %+v", err)
	}
	fp2, err := IdentityFP(message1, user1)
	if err != nil {
		t.Errorf("Failed to create identity fingerprint 2: %+v", err)
	}
	if bytes.Compare(fp1, fp2) != 0 {
		t.Errorf("ID1 [%+v] and ID2 [%+v] were composed from the same data, should have been identical", fp1, fp2)
	}

	// Ensure that changing the message data alters the fingerprint
	fp3, err := IdentityFP(message2, user1)
	if err != nil {
		t.Errorf("Failed to create identity fingerprint 3: %+v", err)
	}
	if bytes.Compare(fp1, fp3) == 0 {
		t.Errorf("ID1 [%+v] and ID3 [%+v] had different messages, should have been different", fp1, fp3)
	}

	// Ensure that changing the user data alters the fingerprint
	fp4, err := IdentityFP(message1, user2)
	if err != nil {
		t.Errorf("Failed to create identity fingerprint 4: %+v", err)
	}
	if bytes.Compare(fp1, fp4) == 0 {
		t.Errorf("ID1 [%+v] and ID4[%+v] had different users, should have been different", fp1, fp4)
	}

	// Extra test case
	fp5, err := IdentityFP(message2, user2)
	if err != nil {
		t.Errorf("Failed to create identity fingerprint 5: %+v", err)
	}
	if bytes.Compare(fp5, fp1) == 0 || bytes.Compare(fp5, fp3) == 0 || bytes.Compare(fp5, fp4) == 0 {
		t.Errorf("Something went wrong: ids generated with different data should not be identical.")
		t.Logf("\n\tID1 [%+v]\n\tID2 [%+v]\n\tID3 [%+v]\n\tID4 [%+v]\n\tID5 [%+v]\n", fp1, fp2, fp3, fp4, fp5)
	}
}

func TestCheckIdentityFP(t *testing.T) {
	message1 := []byte("I'm an encrypted message!")
	user1 := id.NewIdFromString("zezima", id.User, t)

	// Check that two fingerprints created from the same data are identical
	fp1, err := IdentityFP(message1, user1)
	if err != nil {
		t.Errorf("Failed to create identity fingerprint 1: %+v", err)
	}

	ok, err := CheckIdentityFP(fp1, message1, user1)
	if err != nil || !ok {
		t.Errorf("Should have gotten ok from CheckIdentityFP.  Instead got (%+v, %+v)", ok, err)
	}
}
