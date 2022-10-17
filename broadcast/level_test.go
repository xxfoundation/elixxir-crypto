////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package broadcast

import (
	"testing"
)

// Tests that PrivacyLevel.Verify returns true for all valid values of
// PrivacyLevel.
func TestPrivacyLevel_Verify(t *testing.T) {
	tests := []PrivacyLevel{Public, Private, Secret}

	for _, pl := range tests {
		if !pl.Verify() {
			t.Errorf("PrivacyLevel %s marked invalid.", pl)
		}
	}
}

// Error path: Tests that PrivacyLevel.Verify returns false for invalid values
// of PrivacyLevel.
func TestPrivacyLevel_Verify_Invalid(t *testing.T) {
	tests := []PrivacyLevel{Secret + 1, 255}

	for _, pl := range tests {
		if pl.Verify() {
			t.Errorf("PrivacyLevel %d marked valid.", pl)
		}
	}
}

// Consistency test of PrivacyLevel.String.
func TestPrivacyLevel_String_Consistency(t *testing.T) {
	expectedValues := []string{
		"Public", "Private", "Secret", "INVALID PrivacyLevel: 3"}

	for i, expected := range expectedValues {
		s := PrivacyLevel(i).String()

		if s != expected {
			t.Errorf("Failed to get expected string for PrivacyLevel %d."+
				"\nexpected: %s\nreceived: %s", i, expected, s)
		}
	}
}

// Tests that a PrivacyLevel marshalled with PrivacyLevel.Marshal and
// unmarshalled with UnmarshalPrivacyLevel matches the original.
func TestPrivacyLevel_Marshal_UnmarshalPrivacyLevel(t *testing.T) {
	for pl := range privacyLevelNames {
		s := pl.Marshal()

		newPl, err := UnmarshalPrivacyLevel(s)
		if err != nil {
			t.Errorf("Failed to unmarshal privacy level %s: %+v", pl, err)
		}

		if pl != newPl {
			t.Errorf("Unmarshalled PrivacyLevel does not match original."+
				"\nexpected: %d\nreceived: %d", pl, newPl)
		}
	}
}

// Tests that UnmarshalPrivacyLevel returns an error for an invalid
// PrivacyLevel.
func TestUnmarshalPrivacyLevel_Error(t *testing.T) {
	_, err := UnmarshalPrivacyLevel("This is not a valid PrivacyLevel.")
	if err == nil {
		t.Error("Did not get error for invalid PrivacyLevel")
	}
}

// Checks that the two maps, privacyLevelNames and privacyLevelValues, match.
func TestPrivacyLevel_MapCheck(t *testing.T) {
	if len(privacyLevelNames) != len(privacyLevelValues) {
		t.Errorf("Length of name and value maps do not match."+
			"\nname map:  %d\nvalue map: %d",
			len(privacyLevelNames), len(privacyLevelValues))
	}

	for pl, name := range privacyLevelNames {
		v := privacyLevelValues[name]
		if v != pl {
			t.Errorf("Privacy level in name map does not match the one in the "+
				"value map.\nname map:  %d\nvalue map: %d", v, pl)
		}
	}

	for v, name := range privacyLevelValues {
		pl := privacyLevelNames[name]
		if pl != v {
			t.Errorf("Privacy level name in name map does not match the one "+
				"in the value map.\nname map:  %s\nvalue map: %s", v, pl)
		}
	}
}
