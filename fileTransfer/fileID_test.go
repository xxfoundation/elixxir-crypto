////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package fileTransfer

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"math/rand"
	"reflect"
	"testing"
)

//go:embed testFiles/loremIpsum2.txt
var loremIpsum1 []byte

//go:embed testFiles/loremIpsum2.txt
var loremIpsum2 []byte

//go:embed testFiles/ioremLpsum.txt
var ioremLpsum []byte

// TestNewID_SameFiles tests that NewID returns the same ID for the same file
// data.
func TestNewID_SameFiles(t *testing.T) {
	id1 := NewID(loremIpsum1)
	id2 := NewID(loremIpsum2)

	if !bytes.Equal(id1[:], id2[:]) {
		t.Errorf("IDs for the same file are different.\nfile 1: %s\nfile 2: %s",
			id1, id2)
	}
}

// TestNewID_DifferentFiles tests that NewID returns different IDs for different
// file data.
func TestNewID_DifferentFiles(t *testing.T) {
	id1 := NewID(loremIpsum1)
	id2 := NewID(ioremLpsum)

	if bytes.Equal(id1[:], id2[:]) {
		t.Errorf("IDs for different files are he same.\nfile 1: %s\nfile 2: %s",
			id1, id2)
	}
}

// Tests that a file ID serialised via ID.Marshal and unmarshalled via
// UnmarshalID matches the original.
func TestID_Marshal_UnmarshalID(t *testing.T) {
	for i := 0; i < 10; i++ {
		id := newTestID()

		idBytes := id.Marshal()
		newID := UnmarshalID(idBytes)

		if id != newID {
			t.Errorf("Unmarshalled ID #%d does not match original."+
				"\nexpected: %s\noriginal: %s", i, id, newID)
		}
	}
}

// Consistency test of ID.String.
func TestID_String(t *testing.T) {
	expectedStrings := []string{
		"O+pvWzr23gN0NmxHGeQ6GwZ9ibx/AfH1c5gWWaRP8Xo=",
		"THIVo7U56x5YScYHfbtXIvVxeiiaJm+XZHmBmY6+qJw=",
		"C0s3OXARXoLtb0ElyPpzEeTX3vqSLarneGZn9+k2zU8=",
		"JKv334ZrqlYDg2etYUXeHuj0qLCZPr34iDoK2L6cOXg=",
		"sEiD5WoVao3lY6+kZ9Sd7GpA6aHQB/AzwoIwYb3Q6qU=",
		"n45NpkMBBSINCyloi3NLjqDzypk26EYfENd8luqAp6Y=",
		"ZfYG9qY7fz39JWfBiXnk1g8maG2b8vsmyQH/NUzeFgc=",
		"7ilLOfMrfHgiumT4SrQ8oMbmuRwf076JkENBedOvRJE=",
		"o2kBLbktGE/DnRc0/1cWQolTu2hl/PkrDDoXyQKL6ZE=",
		"TrdknGyTR4AJedGDA1bypUw96rKktEddY6++j7Vph8c=",
		"f1gYUm8YFL6CM1DqsTk18x2ESEUX6SSu94rhUcAHVZI=",
		"WDa3B1iFZQww7CmjcDk0v1CijaECl13tp351hXnqPf4=",
	}

	for i, expected := range expectedStrings {
		id := newTestID()

		if expected != id.String() {
			t.Errorf("ID #%d string does not match expected."+
				"\nexpected: %s\nreceived: %s", i, expected, id.String())
		}

		// fmt.Printf("%q,\n", id.String())
	}
}

// Tests that a file ID can be JSON marshalled and unmarshalled and that the
// result matches the original.
func TestID_JSON_Marshal_Unmarshal(t *testing.T) {
	id := newTestID()

	data, err := json.Marshal(&id)
	if err != nil {
		t.Errorf("Failed to JSON marshal ID: %+v", err)
	}

	var newID ID
	err = json.Unmarshal(data, &newID)
	if err != nil {
		t.Errorf("Failed to JSON unmarshal ID: %+v", err)
	}

	if !reflect.DeepEqual(id, newID) {
		t.Errorf("JSON marshalled and unmarshalled ID does not match original."+
			"\nexpected: %+v\nreceived: %+v", id, newID)
	}
}

// Error path: Tests that ID.UnmarshalJSON returns an error when the data is of
// the wrong length.
func TestID_UnmarshalJSON_LengthError(t *testing.T) {
	data := []byte("invalid")
	data, err := json.Marshal(&data)
	if err != nil {
		t.Errorf("Failed to JSON marshal data: %+v", err)
	}

	var newID ID
	err = json.Unmarshal(data, &newID)
	if err == nil {
		t.Error("Failed to error for invalid data")
	}
}

func newTestID() ID {
	var id ID
	rand.Read(id[:])
	return id
}
