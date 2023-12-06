////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
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

//go:embed testFiles/Jelly-Beans1.jpg
var jellyBeans1 []byte

//go:embed testFiles/Jelly-Beans2.jpg
var jellyBeans2 []byte

//go:embed testFiles/house.tiff
var house []byte

// TestNewID_SameFiles tests that NewID returns the same ID for the same ASCII
// file data.
func TestNewID_SameFiles_ASCII(t *testing.T) {
	id1 := NewID(loremIpsum1)
	id2 := NewID(loremIpsum2)

	if !bytes.Equal(id1[:], id2[:]) {
		t.Errorf("IDs for the same file are different.\nfile 1: %s\nfile 2: %s",
			id1, id2)
	}
}

// TestNewID_DifferentFiles tests that NewID returns different IDs for different
// ASCII file data.
func TestNewID_DifferentFiles_ASCII(t *testing.T) {
	id1 := NewID(loremIpsum1)
	id2 := NewID(ioremLpsum)

	if bytes.Equal(id1[:], id2[:]) {
		t.Errorf("IDs for different files are he same.\nfile 1: %s\nfile 2: %s",
			id1, id2)
	}
}

// TestNewID_SameFiles tests that NewID returns the same ID for the same binary
// file data.
func TestNewID_SameFiles_Binary(t *testing.T) {
	id1 := NewID(jellyBeans1)
	id2 := NewID(jellyBeans2)

	if !bytes.Equal(id1[:], id2[:]) {
		t.Errorf("IDs for the same file are different.\nfile 1: %s\nfile 2: %s",
			id1, id2)
	}
}

// TestNewID_DifferentFiles tests that NewID returns different IDs for different
// binary file data.
func TestNewID_DifferentFiles_Binary(t *testing.T) {
	id1 := NewID(jellyBeans1)
	id2 := NewID(house)

	if bytes.Equal(id1[:], id2[:]) {
		t.Errorf("IDs for different files are he same.\nfile 1: %s\nfile 2: %s",
			id1, id2)
	}
}

// Tests that a file ID serialised via ID.Marshal and unmarshalled via
// UnmarshalID matches the original.
func TestID_Marshal_UnmarshalID(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	fileData := make([]byte, 512)

	for i := 0; i < 10; i++ {
		prng.Read(fileData)
		id := NewID(fileData)

		idBytes := id.Marshal()
		newID, err := UnmarshalID(idBytes)
		if err != nil {
			t.Errorf("Failed to unmarshal ID: %+v", err)
		}

		if id != newID {
			t.Errorf("Unmarshalled ID #%d does not match original."+
				"\nexpected: %s\noriginal: %s", i, id, newID)
		}
	}
}

// Error path: Tests that UnmarshalID returns an error when the data is of the
// wrong length.
func Test_UnmarshalID_LengthError(t *testing.T) {
	data := []byte("invalid")
	_, err := UnmarshalID(data)
	if err == nil {
		t.Error("Failed to error for invalid data")
	}
}

// Consistency test of ID.String.
func TestID_String(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	fileData := make([]byte, 512)

	expectedStrings := []string{
		"Po/2zJFIQEBflQ0reu8XsrlMWWy5t0q1lO9P28/5Ys8=",
		"5RugyARGQxo6U4ScnaDxmBa8EwJGj9qjEEC9jRpSotw=",
		"Os6Al8pQHIi0TNSFqbvk0wBZn3ZN7nnpmBAKouRHNpw=",
		"QjCc42N9bCJdCidSix8sAKjOxDriQKsX+zbuGJ/dVO8=",
		"voa/1b7QeIvICPykrNSP954MeIc6FYGM0vzkSAkx3wc=",
		"wUx5hJ3C5AoxByNio19DkXhOk01mKwyYPQhjLkhsBCE=",
		"Jv2ywOF9mcT9vTbQt6cGjzZIZ80rzVwVTcXYiZycFeU=",
		"GYq1NE9fI5ANg3e8P0cUu/bjvtCZzvKJtFSR8QGqKlA=",
		"7hLC1deqNpkBS2ONrzlPoeEZ2kXjJEs1rqn6N096+Js=",
		"iHMegxbKttsIi5I5lp0gplloDHhmTOB0W8uWlbcYat0=",
		"UwQ4YKRVBJLuVKuZfmW8ibA2Ei9gwmYtmCgSHxKOIMo=",
		"PK+Iw6KpBQUpSmlrijc7qx/bRE0ypGZ6DAXMr8AxFrc=",
	}

	for i, expected := range expectedStrings {
		prng.Read(fileData)
		id := NewID(fileData)

		if expected != id.String() {
			t.Errorf("ID #%d string does not match expected."+
				"\nexpected: %s\nreceived: %s", i, expected, id.String())
		}
	}
}

// Tests that a file ID can be JSON marshalled and unmarshalled and that the
// result matches the original.
func TestID_JSON_Marshal_Unmarshal(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	fileData := make([]byte, 512)
	prng.Read(fileData)
	id := NewID(fileData)

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
		t.Error("Failed to error for invalid data.")
	}
}

// Error path: Tests that ID.UnmarshalJSON returns an error when the data is
// invalid JSON.
func TestID_UnmarshalJSON_JsonError(t *testing.T) {
	data := []byte("invalid")
	data, err := json.Marshal(&data)
	if err != nil {
		t.Errorf("Failed to JSON marshal data: %+v", err)
	}

	var id ID
	err = id.UnmarshalJSON([]byte("invalid JSON"))
	if err == nil {
		t.Error("Failed to error for invalid JSON.")
	}
}
