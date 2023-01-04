////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx network SEZC                                           //
//                                                                            //
// Use of this source code is governed by a license that can be found         //
// in the LICENSE file                                                        //
////////////////////////////////////////////////////////////////////////////////

package message

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"gitlab.com/xx_network/primitives/id"
)

// Verify ID adheres to the stringer interface
var _ fmt.Stringer = ID{}

// Verifies that MakeID does not obviously duplicate returned ID
// objects with different inputs.
func TestMakeID_Unique(t *testing.T) {
	const numTests = 100
	results := make([]ID, numTests)
	inputs := make([][]byte, numTests)
	prng := rand.New(rand.NewSource(42))
	chID := &id.ID{}

	// Generate results
	for i := range results {
		contents := make([]byte, 1000)
		prng.Read(contents)
		inputs[i] = contents
		results[i] = deriveID(chID, 8675309, contents, []byte("extra"),
			[]byte("stuff"))
	}

	// Check the results are different
	for i := 0; i < numTests; i++ {
		for j := 0; j < numTests; j++ {
			if i != j {
				require.NotEqual(t, results[i], results[j])
			}
		}
	}
}

// Verifies that MakeID does not obviously duplicate returned ID
// objects with the same inputs but different channel IDs.
func TestMakeID_Channels_Unique(t *testing.T) {
	const numTests = 100
	prng := rand.New(rand.NewSource(42))

	chID1, chID2 := &id.ID{}, &id.ID{}
	chID2[0] = 1

	// Generate results
	for i := 0; i < numTests; i++ {
		contents := make([]byte, 1000)
		prng.Read(contents)

		a := deriveID(chID1, 8675309, contents, []byte("extra"),
			[]byte("stuff"))
		b := deriveID(chID2, 8675309, contents, []byte("extra"),
			[]byte("stuff"))
		require.NotEqual(t, a, b)
	}
}

// Ensures that the output of MakeID is consistent does not change.
func TestMakeID_Constancy(t *testing.T) {
	prng := rand.New(rand.NewSource(69))
	expectedResults := []string{
		"MsgID-YJZshvyOMFXlz48qwmSHnwkg6zrQcLpVMTjS7av+XXo=",
		"MsgID-Qj9e7R3jpvGsc1PuI3kqSpWBOfBt9ytNgXHJVBVsb8I=",
		"MsgID-KdgNUUfO1WdsidTmkXu3xoWfTj+frHd4p8NJEWpzF6Y=",
		"MsgID-zUHWA9NBZHXSl7f3UPQXDnf5+PEgQ/4BeKTT8SlF5/U=",
		"MsgID-rm0a/bP9gnviq2Mld8ZjP0Bl57lU1h+fI0whkTSNFA0=",
	}
	results := make([]ID, len(expectedResults))

	// Generate results
	chID := &id.ID{}
	for i := range results {
		contents := make([]byte, 1000)
		prng.Read(contents)
		results[i] = deriveID(chID, 8675309, contents, []byte("extra"),
			[]byte("stuff"))
	}

	// Check the results are different
	for i, expected := range expectedResults {
		require.Equal(t, expected, results[i].String())
	}
}

// Tests that ID.Equals accurately determines two of the same ID
// objects are the same and that different IDs are different.
func TestID_Equals(t *testing.T) {
	const numTests = 100
	results := make([]ID, numTests)
	prng := rand.New(rand.NewSource(42))
	chID := &id.ID{}

	// Generate results
	for i := range results {
		contents := make([]byte, 1000)
		prng.Read(contents)
		results[i] = deriveID(chID, 8675309, contents, []byte("extra"),
			[]byte("stuff"))
	}

	// Check that equals is equal when it shouldn't be, and is equal when it
	// should be
	for i := 0; i < numTests; i++ {
		for j := 0; j < numTests; j++ {
			if i != j {
				require.NotEqual(t, results[i], results[j])
			} else {
				require.Equal(t, results[i], results[j])
			}
		}
	}
}

// Tests that byte slice returned by ID.Bytes contains the same data that
// is in the ID and that the result is a copy.
func TestID_Bytes(t *testing.T) {
	const numTests = 100
	results := make([]ID, numTests)
	prng := rand.New(rand.NewSource(9001))
	chID := &id.ID{}

	// Generate message IDs
	for i := range results {
		contents := make([]byte, 1000)
		prng.Read(contents)
		results[i] = deriveID(chID, 8675309, contents, []byte("extra"),
			[]byte("stuff"))
	}

	// Check the bytes are the same and that modifying the copy
	// does not reflect on the original
	for i := range results {
		b := results[i].Bytes()

		require.Equal(t, results[i][:], b)

		// Fill the bytes with random data
		prng.Read(b)

		require.NotEqual(t, results[i], b)
	}
}

// Tests that ID returned by ID.DeepCopy is a copy.
func TestID_DeepCopy(t *testing.T) {
	const numTests = 100
	results := make([]ID, numTests)
	prng := rand.New(rand.NewSource(1337))
	chID := &id.ID{}

	// Generate message IDs
	for i := range results {
		contents := make([]byte, 1000)
		prng.Read(contents)
		results[i] = deriveID(chID, 8675309, contents, []byte("extra"),
			[]byte("stuff"))
	}

	// Check the objects are the same and that modifying the copy does not
	// reflect on the original
	for i := range results {
		dc := results[i].DeepCopy()

		// Check that the deep copy and messageID are the same
		require.Equal(t, results[i], dc)

		// Fill the bytes with random data
		prng.Read(dc[:])

		// Check that the bytes and the message ID are different
		require.NotEqual(t, results[i], dc)
	}
}

// Tests that a ID marshalled via ID.Marshal and unmarshalled with
// UnmarshalID matches the original.
func TestID_Marshal_UnmarshalID(t *testing.T) {
	const numTests = 100
	results := make([]ID, numTests)
	prng := rand.New(rand.NewSource(1337))
	chID := &id.ID{}

	// Generate message IDs
	for i := range results {
		contents := make([]byte, 1000)
		prng.Read(contents)
		results[i] = deriveID(chID, 8675309, contents, []byte("extra"),
			[]byte("stuff"))
	}

	for _, result := range results {
		data := result.Marshal()
		mid, err := UnmarshalID(data)
		require.NoError(t, err)

		require.Equal(t, result, mid)
	}
}

// Error path: Tests that UnmarshalID returns an error for data that is
// not of the correct length
func TestUnmarshalID(t *testing.T) {
	data := make([]byte, IDLen+1)
	expectedErr := fmt.Sprintf(
		unmarshalDataLenErr, len(data), IDLen)

	_, err := UnmarshalID(data)
	require.Error(t, err)
	require.Equal(t, err.Error(), expectedErr)
}

// Tests that a ID JSON marshalled and unmarshalled matches the original.
func TestID_MarshalJSON_UnmarshalJSON(t *testing.T) {
	prng := rand.New(rand.NewSource(1337))
	chID, _ := id.NewRandomID(prng, id.User)
	contents := make([]byte, 1000)
	prng.Read(contents)
	mid := deriveID(chID, 8675309, contents, []byte("extra"),
		[]byte("stuff"))

	data, err := json.Marshal(mid)
	if err != nil {
		t.Fatalf("Failed to JSON marshal ID: %+v", err)
	}

	var newMID ID
	err = json.Unmarshal(data, &newMID)
	if err != nil {
		t.Fatalf("Failed to JSON unmarshal ID: %+v", err)
	}

	if mid != newMID {
		t.Errorf("JSON marshaled and unamrshalled ID does not match "+
			"expected.\nexpected: %s\nreceived: %s", mid, newMID)
	}
}

// Tests that the output of json.Marshal on the ID is consistent. This
// test is important because the ID is saved to storage using the JSON
// marshaler and any changes to this format will break storage.
func TestID_MarshalJSON_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(1337))
	expectedData := []string{
		"\"aSbdvmZLlzePwBxzIbU6TOSQs4KCVofCTaKcfCs0arI=\"",
		"\"TJ7aE8LVRX7uCZxm0+jhuZxbTD1723JduCxXvwH/65E=\"",
		"\"EBZmB5X3XxVqaRgyjxsXNWu/rLor/zpA6rjSm1yJtzk=\"",
		"\"IBXCzXko0lOHRzT+Pff5Kl+H6lU8in7lgsAL8MvgBNI=\"",
		"\"9SWxXiHB8VEy+vpskHL/4VLskEdXQ6KIaK5hXZiMyxY=\"",
		"\"NQ6QM+4RY/VHvvudaaQ809+rw2dMGabDtGyL7IbpqZU=\"",
		"\"w38T5iTugE4WGYPtyNhdht9+tzDGwmoWmloKcqys0Ok=\"",
		"\"4LBpemo2bBK6wKJ3FZCBFf7K8zU4rCAdO0VgN6oUykA=\"",
		"\"24lSL/GzbMrvhRjGU90IXyCIac/0jsR68W7s5uhzdnE=\"",
		"\"r9ggHIlNIAl+CRQERJMN0Xx26npydOHLa/rWuvnatbI=\"",
	}

	for _, expected := range expectedData {
		chID, _ := id.NewRandomID(prng, id.User)
		contents := make([]byte, 1000)
		prng.Read(contents)
		mid := deriveID(chID, 8675309, contents, []byte("extra"),
			[]byte("stuff"))

		data, err := json.Marshal(mid)
		require.NoError(t, err)

		require.Equal(t, expected, string(data))
	}
}
