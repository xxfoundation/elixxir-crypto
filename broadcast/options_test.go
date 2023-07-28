////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package broadcast

import (
	"bytes"
	"reflect"
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

// Unit test of newOptions.
func Test_newOptions(t *testing.T) {
	tests := []struct {
		opts     []ChannelOptions
		expected *Options
	}{
		{nil,
			&Options{AdminLevel: Normal}},
		{[]ChannelOptions{SetAdminLevel(Announcement)},
			&Options{AdminLevel: Announcement}},
		{[]ChannelOptions{SetAdminLevel(Free)},
			&Options{AdminLevel: Free}},
	}

	for i, tt := range tests {
		opts := newOptions(tt.opts...)
		if !reflect.DeepEqual(tt.expected, opts) {
			t.Errorf("Unexpected new options (%d)."+
				"\nexpected: %+v\nreceived: %+v", i, tt.expected, opts)
		}
	}
}

// Consistency test of options.encode.
func Test_options_encode(t *testing.T) {
	tests := []struct {
		opts     *Options
		expected []byte
	}{
		{newOptions(), []byte{}},
		{newOptions(SetAdminLevel(Announcement)), []byte{1}},
		{newOptions(SetAdminLevel(Free)), []byte{2}},
	}

	for i, tt := range tests {
		encoded := tt.opts.encode()
		if !bytes.Equal(encoded, tt.expected) {
			t.Errorf("Failed to get expected encoding for options %d: %+v"+
				"\nexpected: %d\nreceived: %d", i, tt.opts, tt.expected, encoded)
		}
	}
}

// Tests that an options object encoded with options.encodeForURL and decoded
// with options.decodeFromURL matches the original.
func Test_options_encodeForURL_decodeFromURL(t *testing.T) {
	tests := []*Options{
		newOptions(),
		newOptions(SetAdminLevel(Announcement)),
		newOptions(SetAdminLevel(Free)),
	}

	for i, expected := range tests {
		encoded := expected.encodeForURL()

		opts := newOptions()
		err := opts.decodeFromURL(encoded)
		if err != nil {
			t.Errorf("Failed to decode from URL (%d): %+v", i, err)
		}
		if !reflect.DeepEqual(expected, opts) {
			t.Errorf("Unexpected decoded options from URL (%d)."+
				"\nexpected: %+v\nreceived: %+v", i, expected, opts)
		}
	}
}

// Tests that options.decodeFromURL does not modify the options for an empty
// string.
func Test_options_decodeFromURL_EmptyURL(t *testing.T) {
	opts := newOptions(SetAdminLevel(Announcement))
	expected := newOptions(SetAdminLevel(Announcement))

	err := opts.decodeFromURL("")
	if err != nil {
		t.Errorf("Failed to decode from empty string: %+v", err)
	}

	if !reflect.DeepEqual(expected, opts) {
		t.Errorf("Options was modified from empty string."+
			"\nexpected: %+v\nreceived: %+v", expected, opts)
	}
}

// Error path: Tests that an options returns errors for invalid fields.
func Test_options_decodeFromURL_DecoderErrors(t *testing.T) {
	tests := []string{"a"}

	for i, invalid := range tests {
		err := newOptions().decodeFromURL(invalid)
		if err == nil {
			t.Errorf("Failed to receive error for invalid string (%d): %q",
				i, invalid)
		}
	}
}

// Tests that an options object encoded with options.prettyPrint and decoded
// with newOptionsFromPrettyPrint matches the original.
func Test_options_prettyPrint_newOptionsFromPrettyPrint(t *testing.T) {
	tests := []*Options{
		newOptions(),
		newOptions(SetAdminLevel(Announcement)),
		newOptions(SetAdminLevel(Free)),
	}

	for i, expected := range tests {
		prettyPrint := expected.prettyPrint()

		opts, err := newOptionsFromPrettyPrint(prettyPrint)
		if err != nil {
			t.Errorf("Failed to decode from pretty print (%d): %+v", i, err)
		}
		if !reflect.DeepEqual(expected, opts) {
			t.Errorf("Unexpected decoded options from pretty print (%d)."+
				"\nexpected: %+v\nreceived: %+v", i, expected, opts)
		}
	}
}

// Error path: Tests that newOptionsFromPrettyPrint returns an error when an
// option is has the wrong delimiter.
func Test_newOptionsFromPrettyPrint_InvalidFieldError(t *testing.T) {
	invalid := oppHead + oppAdminLevel + "=" + Free.marshalText() + oppTail
	_, err := newOptionsFromPrettyPrint(invalid)
	if err == nil {
		t.Errorf("Failed to receive error for fake field: %q", invalid)
	}
}

// Error path: Tests that newOptionsFromPrettyPrint returns the expected errors
// for different invalid fields.
func Test_newOptionsFromPrettyPrint_DecodeErrors(t *testing.T) {
	tests := []string{oppAdminLevel + oppFieldDelim + "some value"}

	for i, invalid := range tests {
		invalid = oppHead + invalid + oppTail
		_, err := newOptionsFromPrettyPrint(invalid)
		if err == nil {
			t.Errorf("Failed to receive error for invalid field (%d): %q",
				i, invalid)
		}
	}
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
