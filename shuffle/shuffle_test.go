////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package shuffle

import (
	"errors"
	"math"
	"strconv"
	"testing"
)

type AlwaysErrorReader struct{}

func (r AlwaysErrorReader) Read(b []byte) (int, error) {
	return 1, errors.New("testing reader error")
}

func (r AlwaysErrorReader) SetSeed(seed []byte) error {
	return nil
}

func TestShuffle32(t *testing.T) {
	// TODO: calculate false failure rate

	// Shuffle a bunch of small lists
	reps := 100000
	batch := 4

	var outInts [][]uint32

	for i := 0; i < reps; i++ {

		var intLst []uint32

		for j := uint32(0); j < uint32(batch); j++ {
			intLst = append(intLst, j)
		}
		outInts = append(outInts, intLst)
	}

	for i := 0; i < reps; i++ {
		Shuffle32(&(outInts[i]))
	}

	// Count the number of times that a particular number ended up in a
	// particular place
	var intPlacementCounts [][]int

	for i := 0; i < batch; i++ {
		intPlacementCounts = append(intPlacementCounts, make([]int,
			int(batch)))
	}

	for i := 0; i < reps; i++ {
		for j := 0; j < batch; j++ {
			intPlacementCounts[j][outInts[i][j]]++
		}
	}

	// Find out how different it was from what we expected
	totalDeviationFromExpected := 0
	t.Log("Probabilities that each number ended up in each slot:")
	for i := 0; i < batch; i++ {
		tableLogRow := ""
		for j := 0; j < batch; j++ {
			totalDeviationFromExpected += int(math.Abs(float64(
				intPlacementCounts[i][j] - reps/batch)))
			// Log probability that a number ends up here
			tableLogCell := strconv.FormatFloat(float64(
				intPlacementCounts[i][j])/float64(
				reps), 'f', 4, 64)
			tableLogRow += tableLogCell
			tableLogRow += "\t"
		}
		t.Log(tableLogRow)
	}
	t.Logf("Total deviation from expected probabilities: %v",
		totalDeviationFromExpected)

	// TODO: calculate what the expected maximum deviation should actually be
	expectedMaximumDeviation := 3000
	if totalDeviationFromExpected > expectedMaximumDeviation {
		t.Errorf("Got more deviation from even shuffle probabilities than"+
			" expected. Got: %v, expected less than %v.",
			totalDeviationFromExpected, expectedMaximumDeviation)
	} else {
		t.Log("Shuffle() 1 out of 1 tests passed.\n")
	}
}

// Test the shuffle on a list of length 1
func TestShuffleLen1_32(t *testing.T) {
	var testlst []uint32
	testlst = append(testlst, 1)
	Shuffle32(&testlst)
}

// Test that shuffleCore panics on read error
func TestShuffleCorePanic32(t *testing.T) {
	var testlst []uint32
	testlst = append(testlst, 1)
	testlst = append(testlst, 2)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Shuffle should panic on read error")
		}
	}()

	shuffleCore32(&testlst, AlwaysErrorReader{})
}

func TestShuffle(t *testing.T) {
	// TODO: calculate false failure rate

	// Shuffle a bunch of small lists
	reps := 100000
	batch := 4

	var outInts [][]uint64

	for i := 0; i < reps; i++ {

		var intLst []uint64

		for j := uint64(0); j < uint64(batch); j++ {
			intLst = append(intLst, j)
		}
		outInts = append(outInts, intLst)
	}

	for i := 0; i < reps; i++ {
		Shuffle(&(outInts[i]))
	}

	// Count the number of times that a particular number ended up in a
	// particular place
	var intPlacementCounts [][]int

	for i := 0; i < batch; i++ {
		intPlacementCounts = append(intPlacementCounts, make([]int,
			int(batch)))
	}

	for i := 0; i < reps; i++ {
		for j := 0; j < batch; j++ {
			intPlacementCounts[j][outInts[i][j]]++
		}
	}

	// Find out how different it was from what we expected
	totalDeviationFromExpected := 0
	t.Log("Probabilities that each number ended up in each slot:")
	for i := 0; i < batch; i++ {
		tableLogRow := ""
		for j := 0; j < batch; j++ {
			totalDeviationFromExpected += int(math.Abs(float64(
				intPlacementCounts[i][j] - reps/batch)))
			// Log probability that a number ends up here
			tableLogCell := strconv.FormatFloat(float64(
				intPlacementCounts[i][j])/float64(
				reps), 'f', 4, 64)
			tableLogRow += tableLogCell
			tableLogRow += "\t"
		}
		t.Log(tableLogRow)
	}
	t.Logf("Total deviation from expected probabilities: %v",
		totalDeviationFromExpected)

	// TODO: calculate what the expected maximum deviation should actually be
	expectedMaximumDeviation := 3000
	if totalDeviationFromExpected > expectedMaximumDeviation {
		t.Errorf("Got more deviation from even shuffle probabilities than"+
			" expected. Got: %v, expected less than %v.",
			totalDeviationFromExpected, expectedMaximumDeviation)
	} else {
		t.Log("Shuffle() 1 out of 1 tests passed.\n")
	}
}

// Test the shuffle on a list of length 1
func TestShuffleLen1(t *testing.T) {
	var testlst []uint64
	testlst = append(testlst, 1)
	Shuffle(&testlst)
}

// Test that shuffleCore panics on read error
func TestShuffleCorePanic(t *testing.T) {
	var testlst []uint64
	testlst = append(testlst, 1)
	testlst = append(testlst, 2)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Shuffle should panic on read error")
		}
	}()

	shuffleCore(&testlst, AlwaysErrorReader{})
}
