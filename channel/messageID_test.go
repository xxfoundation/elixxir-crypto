package channel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"gitlab.com/xx_network/primitives/id"
	"math/rand"
	"testing"
)

// Verify MessageID adheres to the stringer interface
var _ fmt.Stringer = MessageID{}

// Verifies that MakeMessageID does not obviously duplicate returned MessageID
// objects with different inputs.
func TestMakeMessageID_Unique(t *testing.T) {
	const numTests = 100
	results := make([]MessageID, numTests)
	inputs := make([][]byte, numTests)
	prng := rand.New(rand.NewSource(42))
	chID := &id.ID{}

	// Generate results
	for i := range results {
		contents := make([]byte, 1000)
		prng.Read(contents)
		inputs[i] = contents
		results[i] = MakeMessageID(contents, chID)
	}

	// Check the results are different
	for i := 0; i < numTests; i++ {
		for j := 0; j < numTests; j++ {
			if i != j {
				if bytes.Equal(results[i][:], results[j][:]) {
					t.Fatalf("Result %d and %d are the same for ID %s."+
						"\nID %d: %v\nID %d: %v", i, j,
						results[i], i, inputs[i], j, inputs[j])
				}
			}
		}
	}
}

// Verifies that MakeMessageID does not obviously duplicate returned MessageID
// objects with the same inputs but different channel IDs.
func TestMakeMessageID_Channels_Unique(t *testing.T) {
	const numTests = 100
	prng := rand.New(rand.NewSource(42))

	chID1, chID2 := &id.ID{}, &id.ID{}
	chID2[0] = 1

	// Generate results
	for i := 0; i < numTests; i++ {
		contents := make([]byte, 1000)
		prng.Read(contents)

		a := MakeMessageID(contents, chID1)
		b := MakeMessageID(contents, chID2)
		if a.Equals(b) {
			t.Errorf("MessageID with same contents but different channel IDs "+
				"are equal (%d)."+
				"\ncontents:     %q...\nChannel ID a: %s\nChannel ID b: %s"+
				"\nMessageID a:  %s\nMessageID b:  %s",
				i, contents[:16], chID1, chID2, a, b)
		}
	}
}

// Ensures that the output of MakeMessageID is consistent does not change.
func TestMakeMessageID_Constancy(t *testing.T) {
	prng := rand.New(rand.NewSource(69))
	expectedResults := []string{
		"ChMsgID-936YPj78YUr6bJ9LrGILBeCBFCwB3aIwxX0UL3mMjtE=",
		"ChMsgID-m+7QPDIGaDR2TFeksDH2JlikZAeU+E/f0amzCVlTYrY=",
		"ChMsgID-ob/cikchYn1MBymZv8O0kv3Y5cxA3h4u2sCnlkSVaWM=",
		"ChMsgID-ATMGXTjZL/GjY8HhS3hAUzAGudluCVA/062dhQsNvBw=",
		"ChMsgID-spm/UbyfvrkmLiwZWB7DkyY30gXDWnwZM/90t0UsfFg=",
	}
	results := make([]MessageID, len(expectedResults))

	// Generate results
	chID := &id.ID{}
	for i := range results {
		contents := make([]byte, 1000)
		prng.Read(contents)
		results[i] = MakeMessageID(contents, chID)
	}

	// Check the results are different
	for i, expected := range expectedResults {
		if results[i].String() != expected {
			t.Errorf("Result %d did not match expected."+
				"\nexpected: %s\nreceived: %s", i, expected, results[i])
		}
	}
}

// Tests that MessageID.Equals accurately determines two of the same MessageID
// objects are the same and that different IDs are different.
func TestMessageID_Equals(t *testing.T) {
	const numTests = 100
	results := make([]MessageID, numTests)
	prng := rand.New(rand.NewSource(42))
	chID := &id.ID{}

	// Generate results
	for i := range results {
		contents := make([]byte, 1000)
		prng.Read(contents)
		results[i] = MakeMessageID(contents, chID)
	}

	// Check that equals is equal when it shouldn't be, and is equal when it
	// should be
	for i := 0; i < numTests; i++ {
		for j := 0; j < numTests; j++ {
			if i != j {
				if results[i].Equals(results[j]) {
					t.Fatalf("Result %d and %d are not the same when they "+
						"should be.\nID %d: %v\nID %d: %v",
						i, j, i, results[i], j, results[j])
				}
			} else {
				if !bytes.Equal(results[i][:], results[j][:]) {
					t.Fatalf("Result %d and %d are the same when they should "+
						"not be.\nID %d: %v\nID %d: %v",
						i, j, i, results[i], j, results[j])

				}
			}
		}
	}
}

// Tests that byte slice returned by MessageID.Bytes contains the same data that
// is in the MessageID and that the result is a copy.
func TestMessageID_Bytes(t *testing.T) {
	const numTests = 100
	results := make([]MessageID, numTests)
	prng := rand.New(rand.NewSource(9001))
	chID := &id.ID{}

	// Generate message IDs
	for i := range results {
		contents := make([]byte, 1000)
		prng.Read(contents)
		results[i] = MakeMessageID(contents, chID)
	}

	// Check the bytes are the same and that modifying the copy does not reflect
	// on the original
	for i := range results {
		b := results[i].Bytes()

		// Check that the bytes and messageID are the same
		if !bytes.Equal(results[i][:], b) {
			t.Errorf("Result %d bytes is not the same as the source."+
				"\nexpected: %v\nreceived: %v", i, results[i][:], b)
		}

		// Fill the bytes with random data
		prng.Read(b)

		// Check that the bytes and the message ID are different
		if bytes.Equal(results[i][:], b) {
			t.Errorf("Result %d bytes is the same as the source after editing."+
				"\nsource: %v\nresult: %v", i, results[i][:], b)
		}
	}
}

// Tests that MessageID returned by MessageID.DeepCopy is a copy.
func TestMessageID_DeepCopy(t *testing.T) {
	const numTests = 100
	results := make([]MessageID, numTests)
	prng := rand.New(rand.NewSource(1337))
	chID := &id.ID{}

	// Generate message IDs
	for i := range results {
		contents := make([]byte, 1000)
		prng.Read(contents)
		results[i] = MakeMessageID(contents, chID)
	}

	// Check the objects are the same and that modifying the copy does not
	// reflect on the original
	for i := range results {
		dc := results[i].DeepCopy()

		// Check that the deep copy and messageID are the same
		if !results[i].Equals(dc) {
			t.Errorf("Result %d deep copy is not the same as the source."+
				"\nsource: %s\ncopy:   %s", i, results[i], dc)
		}

		// Fill the bytes with random data
		prng.Read(dc[:])

		// Check that the bytes and the message ID are different
		if results[i].Equals(dc) {
			t.Errorf("Result %d deep copy is the same as the source after "+
				"editing.\nsource: %s\ncopy:   %s", i, results[i], dc)
		}
	}
}

// Tests that a MessageID marshalled via MessageID.Marshal and unmarshalled with
// UnmarshalMessageID matches the original.
func TestMessageID_Marshal_UnmarshalMessageID(t *testing.T) {
	const numTests = 100
	results := make([]MessageID, numTests)
	prng := rand.New(rand.NewSource(1337))
	chID := &id.ID{}

	// Generate message IDs
	for i := range results {
		contents := make([]byte, 1000)
		prng.Read(contents)
		results[i] = MakeMessageID(contents, chID)
	}

	for i, result := range results {
		data := result.Marshal()
		mid, err := UnmarshalMessageID(data)
		if err != nil {
			t.Errorf("Failed to unmarshal MessageID %d: %+v", i, err)
		}

		if !result.Equals(mid) {
			t.Errorf("Marshalled and Unmarshalled MessageID does not match "+
				"oirignal.\nexpected: %s\nreceived: %s", result, mid)
		}
	}
}

// Error path: Tests that UnmarshalMessageID returns an error for data that is
// not of the correct length
func TestUnmarshalMessageID(t *testing.T) {
	data := make([]byte, MessageIDLen+1)
	expectedErr := fmt.Sprintf(
		unmarshalMessageIdDataLenErr, len(data), MessageIDLen)

	_, err := UnmarshalMessageID(data)
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Did not get expected error for data of incorrect length."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Tests that a MessageID JSON marshalled and unmarshalled matches the original.
func TestMessageID_MarshalJSON_UnmarshalJSON(t *testing.T) {
	prng := rand.New(rand.NewSource(1337))
	chID, _ := id.NewRandomID(prng, id.User)
	contents := make([]byte, 1000)
	prng.Read(contents)
	mid := MakeMessageID(contents, chID)

	data, err := json.Marshal(mid)
	if err != nil {
		t.Fatalf("Failed to JSON marshal MessageID: %+v", err)
	}

	var newMID MessageID
	err = json.Unmarshal(data, &newMID)
	if err != nil {
		t.Fatalf("Failed to JSON unmarshal MessageID: %+v", err)
	}

	if mid != newMID {
		t.Errorf("JSON marshaled and unamrshalled MessageID does not match "+
			"expected.\nexpected: %s\nreceived: %s", mid, newMID)
	}
}

// Tests that the output of json.Marshal on the MessageID is consistent. This
// test is important because the MessageID is saved to storage using the JSON
// marshaler and any changes to this format will break storage.
func TestMessageID_MarshalJSON_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(1337))
	expectedData := []string{
		`"JK2k7J12VtoLtHRwLwPoXKbsuDXt+b2oyWCYJyk/xFc="`,
		`"STtKvxCEDy/UCfwIyq9v23B3X8eV1KqSB1CoAtitdk8="`,
		`"uFts/Ug2D/A1A5WDifVuX7e5UZCelEo7rpLBLmhc/sI="`,
		`"KZbCLx+aFVghkYymeU4/f18db8TDKRjcCoRW79WmEzY="`,
		`"WEEwQ7d8b+UpcvymJliO7O4L5seD5FozTbWZIQQAcrY="`,
		`"QEF6vG9W+/gerI3ThHtPtn4KKYCW69ebBfKLnyj6yqI="`,
		`"fLBJTa6VkGxzHslAwpPIvr33enRNKmNAGLsGYjfocRk="`,
		`"n2RCe4m55XkwPiV2tig6gA28cLUDQK9dwDrELlePTxI="`,
		`"YmUVG3T41F70bhrNlx+8J6CYt51iKf2qJmKHsmIpBPY="`,
		`"Qt1hNDqE8g4gEOa0OCk2BSEPBoY34WhT7B1+UyGh2Zg="`,
	}

	for i, expected := range expectedData {
		chID, _ := id.NewRandomID(prng, id.User)
		contents := make([]byte, 1000)
		prng.Read(contents)
		mid := MakeMessageID(contents, chID)

		data, err := json.Marshal(mid)
		if err != nil {
			t.Errorf("Failed to JSON marshal message ID: %+v", err)
		}

		if expected != string(data) {
			t.Errorf("Unexpected JSON for MessageID %s (%d)."+
				"\nexpected: %s\nreceived: %s", mid, i, expected, data)
		}
	}
}
