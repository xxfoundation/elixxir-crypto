////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package broadcast

import (
	"bytes"
	"testing"
)

////////////////////////////////////////////////////////////////////////////////
// Channel Option Functions                                                   //
////////////////////////////////////////////////////////////////////////////////

func TestSetAdminLevel(t *testing.T) {
}

////////////////////////////////////////////////////////////////////////////////
// Options Structure                                                          //
////////////////////////////////////////////////////////////////////////////////

// Unit test of NewOptions.
func TestNewOptions(t *testing.T) {
	expected := Options{AdminLevel: DefaultAdminLevel}

	opts := NewOptions()
	if expected != opts {
		t.Errorf("Unexpected new Options."+
			"\nexpected: %+v\nreceived: %+v", expected, opts)
	}
}

func TestOptions_encode(t *testing.T) {
}

func TestOptions_encodeForURL(t *testing.T) {
}

func TestOptions_decodeFromURL(t *testing.T) {
}

func TestOptions_prettyPrint(t *testing.T) {
}

func Test_newOptionsFromPrettyPrint(t *testing.T) {
}

////////////////////////////////////////////////////////////////////////////////
// AdminLevel                                                                 //
////////////////////////////////////////////////////////////////////////////////

// Consistency test of AdminLevel.marshal.
func TestAdminLevel_marshal(t *testing.T) {
	tests := map[AdminLevel][]byte{
		Normal:       {0},
		Announcement: {1},
		Free:         {2},
	}

	for al, expected := range tests {
		b := al.marshal()
		if !bytes.Equal(expected, b) {
			t.Errorf("Incorrect bytes for AdminLevel %s."+
				"\nexpected: %d\nreceived: %d", al, expected, b)
		}
	}
}

// Tests that an AdminLevel marshalled by AdminLevel.marshalText can be
// unmarshalled by unmarshalAdminLevelText.
func TestAdminLevel_marshalText_unmarshalAdminLevelText(t *testing.T) {
	tests := []AdminLevel{
		Normal,
		Announcement,
		Free,
	}

	for i, expected := range tests {
		text := expected.marshalText()

		al, err := unmarshalAdminLevelText(text)
		if err != nil {
			t.Errorf("Failed to unmarshal text for AdminLevel (%d)."+
				"\nexpected: %d\nreceived: %d", i, expected, al)
		}
	}
}

// Error path: Tests that AdminLevel.marshalText panics for an invalid
// AdminLevel.
func TestAdminLevel_marshalText_InvalidAdminLevelPanic(t *testing.T) {
	al := AdminLevel(99)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Failed to panic for invalid AdminLevel.")
		}
	}()

	al.marshalText()
}

// Error path: Tests that unmarshalAdminLevelText return an error for an invalid
// string
func Test_unmarshalAdminLevelText_InvalidTextError(t *testing.T) {
	_, err := unmarshalAdminLevelText("some string")
	if err == nil {
		t.Errorf("Failed to get error for invalid string")
	}
}

// Consistency test of AdminLevel.String.
func TestAdminLevel_String(t *testing.T) {
	tests := map[AdminLevel]string{
		Normal:       "normal",
		Announcement: "announcement",
		Free:         "free",
		99:           "INVALID ADMIN LEVEL: 99",
	}

	for al, expected := range tests {
		if al.String() != expected {
			t.Errorf("Unexpected string for AdminLevel %d."+
				"\nexpected: %s\nreceived: %s", al, expected, al.String())
		}
	}
}
