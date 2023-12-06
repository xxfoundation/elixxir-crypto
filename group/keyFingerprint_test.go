////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package group

import (
	"gitlab.com/xx_network/primitives/id"
	"math/rand"
	"testing"
)

// Consistency test of NewKeyFingerprint.
func TestNewKeyFingerprint_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	expectedFPs := []string{
		"Y7Yg9nl3GuIOx2Tux5OmfHIFDEq+vIwBH7n4cm/uzgE=",
		"SrzCmuQsTSRaZReZt7P9eQb25Pzyyn+rgMFGluH5bZs=",
		"UQbf+fFVLC8uEbFjvE+qyeJCfxgudZ+jRXZmLwzQvbc=",
		"eCmiiItzszUi7EphXjsItUbRkNQ5I94Cukgs+9wko18=",
		"bcl5p+JQaHR8uxCdZ9dAD2AOHXa3ageMuo9KoLl63+g=",
		"By18RQhDXYeatNA3zvL2PPYNfi3ZUZhe6VhYtr26Sr4=",
		"FqXBUimB6egtSh1C1QLQAWVLRh8PmkYLI4V1vIHKWY0=",
		"L5XKj7C8m9X+YMWfPNFG6sgktTOlxotO1mRl29gV3GM=",
		"Qz++Oluf5SpsKyyQuXwP93ytq3yVitq8tHFJJPlq5cY=",
		"S6CKGQIp0w6DYZcp5vuDcywFnQIEhaKf9NF16nzeCLs=",
	}

	for i, expected := range expectedFPs {
		groupKey := [KeyLen]byte{}
		prng.Read(groupKey[:])
		var salt [SaltLen]byte
		prng.Read(salt[:])
		rid := randID(prng, id.User)

		keyFp := NewKeyFingerprint(groupKey, salt, rid)

		if expected != keyFp.String() {
			t.Errorf("NewKeyFingerprint did not return the expected fingerprint (%d)."+
				"\nexpected: %s\nreceived: %s", i, expected, keyFp)
		}

		// Ensure the first bit is zero
		if keyFp[0]>>7 != 0 {
			t.Errorf("NewKeyFingerprint produced a fingerprint without the first bit being 0 (%d)."+
				"\nexpected: %d\nreceived: %d", i, 0, keyFp[0]>>7)
		}

		// fmt.Printf("\"%s\",\n", keyFP)
	}
}

// Test that NewKeyFingerprint returns unique fingerprints when the group key,
// salt, and recipient ID are changed individually.
func TestNewKeyFingerprint_Unique(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	fps := map[string]bool{}
	groupKey := [KeyLen]byte{}
	prng.Read(groupKey[:])
	var salt [SaltLen]byte
	prng.Read(salt[:])
	rid := randID(prng, id.User)

	// Test changes to group key
	for i := 0; i < 100; i++ {
		keyFp := NewKeyFingerprint(groupKey, salt, rid)

		if fps[keyFp.String()] {
			t.Errorf("Fingerprint %s already exists in the map (%d).", keyFp, i)
		} else {
			fps[keyFp.String()] = true
		}

		prng.Read(groupKey[:])
	}

	// Test changes to group salt
	for i := 0; i < 100; i++ {
		keyFp := NewKeyFingerprint(groupKey, salt, rid)

		if fps[keyFp.String()] {
			t.Errorf("Fingerprint %s already exists in the map (%d).", keyFp, i)
		} else {
			fps[keyFp.String()] = true
		}

		prng.Read(salt[:])
	}

	// Test changes to recipient ID
	for i := 0; i < 100; i++ {
		keyFp := NewKeyFingerprint(groupKey, salt, rid)

		if fps[keyFp.String()] {
			t.Errorf("Fingerprint %s already exists in the map (%d).", keyFp, i)
		} else {
			fps[keyFp.String()] = true
		}

		rid = randID(prng, id.User)
	}
}

// Unit test of CheckKeyFingerprint.
func TestCheckKeyFingerprint(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	groupKey := [KeyLen]byte{}
	prng.Read(groupKey[:])
	var salt [SaltLen]byte
	prng.Read(salt[:])
	rid := randID(prng, id.User)

	keyFP := NewKeyFingerprint(groupKey, salt, rid)
	check := CheckKeyFingerprint(keyFP, groupKey, salt, rid)

	if !check {
		t.Error("CheckKeyFingerprint failed to confirm the fingerprint.")
	}
}
