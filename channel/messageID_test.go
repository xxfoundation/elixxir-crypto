package channel

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
)

// verify MessageID adheres to the stringer interface
var _ fmt.Stringer = MessageID{}

// TestMakeMessageID_Unique verifies that MakeMessageID doesnt obviously
// duplicate returned message IDs
func TestMakeMessageID_Unique(t *testing.T) {

	numTests := 100
	results := make([]MessageID, 0, numTests)
	inputs := make([][]byte, 0, numTests)
	prng := rand.New(rand.NewSource(42))

	// generate results
	for i :=0;i<numTests;i++{
		contents := make([]byte, 1000)
		prng.Read(contents)
		inputs = append(inputs, contents)
		results = append(results, MakeMessageID(contents))
	}

	//Check the results are different
	for i:=0;i<numTests; i++{
		for j:=0;j<numTests;j++{
			if i!=j{
				if bytes.Equal(results[i][:],results[j][:]){
					t.Fatalf("Result %d and %d are the same " +
						"with %s, inputs: %v vs %v", i, j, results[i], inputs[i], inputs[j])
				}
			}
		}
	}
}

// TestMakeMessageID_Constancy ensures the output of the function doesnt change
func TestMakeMessageID_Constancy(t *testing.T) {

	numTests := 5
	results := make([]MessageID, 0, numTests)
	prng := rand.New(rand.NewSource(69))

	expectedResults := []string{
		"ChMsgID-AlkzMbRYRiIS9Dm+uSWCqgJ8QTWlXygFAp/kpM/Oy3A=",
		"ChMsgID-jv5SK77OMmZLLk4zNVQ/L4C130SH8OqayPZE62OrvUY=",
		"ChMsgID-aKA3mZUlgvXxy3gibg8d2emfCbIlgrAql9rYYsT1a0w=",
		"ChMsgID-bDYgDqlHKq82oYgI0M39sLMlRpAuBpBV/y4PkI1/clw=",
		"ChMsgID-aHSHIUanQExfrg7ChaP8SG0DTfPPJtEw9ht4g5+sVJo=",
	}

	// generate results
	for i :=0;i<numTests;i++{
		contents := make([]byte, 1000)
		prng.Read(contents)
		results = append(results, MakeMessageID(contents))
	}

	//Check the results are different
	for i:=0;i<numTests; i++{
		if results[i].String()!=expectedResults[i]{
			t.Errorf("Result %d did not match expected results, '%s' " +
				"vs '%s' ", i, results[i], expectedResults[i])
		}
	}
}

// TestMessageID_Equals makes sure the equals function works
func TestMessageID_Equals(t *testing.T) {

	numTests := 100
	results := make([]MessageID, 0, numTests)
	inputs := make([][]byte, 0, numTests)
	prng := rand.New(rand.NewSource(420))

	// generate message IDs
	for i :=0;i<numTests;i++{
		contents := make([]byte, 1000)
		prng.Read(contents)
		inputs = append(inputs, contents)
		results = append(results, MakeMessageID(contents))
	}

	// Check that equals is equal when it shouldn't be, and is equal when it
	// should be
	for i:=0;i<numTests; i++{
		for j:=0;j<numTests;j++{
			if i!=j{
				if results[i].Equals(results[j]){
					t.Fatalf("Result %d and %d are not the same when they should be" +
						"with %s, inputs: %v vs %v", i, j, results[i], inputs[i], inputs[j])
				}
			}else{
				if !bytes.Equal(results[i][:],results[j][:]){
					t.Fatalf("Result %d and %d are the same when they should not be" +
						"with %s, inputs: %v vs %v", i, j, results[i], inputs[i], inputs[j])
				}
			}
		}
	}
}

// TestMakeMessageID_Bytes makes sure the bytes function returns the same data
// and that it is a copy
func TestMessageID_Bytes(t *testing.T) {

	numTests := 100
	results := make([]MessageID, 0, numTests)
	prng := rand.New(rand.NewSource(9001))

	// generate message IDs
	for i :=0;i<numTests;i++{
		contents := make([]byte, 1000)
		prng.Read(contents)
		results = append(results, MakeMessageID(contents))
	}

	// Check the bytes are the same and that modifying them doesnt modify the ID
	for i:=0;i<numTests; i++{
		b := results[i].Bytes()
		//check that the bytes and messageID are the same
		if !bytes.Equal(results[i][:],b){
			t.Errorf("Result %d bytes is not the same as the source, " +
				"'%v' vs '%v' ", i, results[i][:], b)
		}
		//fill the bytes with random data
		prng.Read(b)
		//check that the bytes and the message ID are different
		if bytes.Equal(results[i][:],b){
			t.Errorf("Result %d bytes is the same as the source after " +
				"editing, '%v' vs '%v' ", i, results[i][:], b)
		}
	}
}

// TestMakeMessageID_Bytes makes sure the bytes function returns the same data
// and that it is a copy
func TestMessageID_DeepCopy(t *testing.T) {

	numTests := 100
	results := make([]MessageID, 0, numTests)
	prng := rand.New(rand.NewSource(1337))

	// generate message IDs
	for i :=0;i<numTests;i++{
		contents := make([]byte, 1000)
		prng.Read(contents)
		results = append(results, MakeMessageID(contents))
	}

	// Check the bytes are the same and that modifying them doesnt modify the ID
	for i:=0;i<numTests; i++{
		dc := results[i].DeepCopy()
		//check that the deep copy and messageID are the same
		if !results[i].Equals(dc){
			t.Errorf("Result %d deep copy is not the same as the " +
				"source, '%s' vs '%s' ", i, results[i], dc)
		}
		//fill the bytes with random data
		prng.Read(dc[:])
		//check that the bytes and the message ID are different
		if results[i].Equals(dc){
			t.Errorf("Result %d deep copy is the same as the source " +
				"after editing, '%s' vs '%s' ", i, results[i], dc)
		}
	}
}
