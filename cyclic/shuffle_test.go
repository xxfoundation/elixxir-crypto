package cyclic

import (
	"math"
	"testing"
)

func TestShuffle(t *testing.T) {
	// assuming the number system is circular, averages the movement of each
	// shuffle.  The result should be that the average shuffle is 1/4 the
	// batch size.
	// TODO: calulate false failure rate

	reps := uint64(100)
	batch := uint64(2000)

	min := float64(0.48)
	max := float64(0.52)

	var outInts [][]uint64

	for i := uint64(0); i < reps; i++ {

		var intLst []uint64

		for j := uint64(0); j < batch; j++ {
			intLst = append(intLst, j)
		}
		outInts = append(outInts, intLst)
	}

	for i := uint64(0); i < reps; i++ {
		Shuffle(&(outInts[i]))
	}

	sumDelta := float64(0)
	numElements := float64(batch * reps)

	halfBatch := float64(batch) / float64(2.0)

	for i := uint64(0); i < reps; i++ {

		for j := uint64(0); j < batch; j++ {

			newDelta := circularDelta(outInts[i][j], j, batch)
			newDelta /= halfBatch

			sumDelta += newDelta

		}

	}

	avgDelta := sumDelta / numElements

	if (avgDelta < min) || (avgDelta > max) {
		t.Errorf("Test of Shuffle failed, "+
			"expected delta between: '%v' and '%v', got: '%v'",
			min, max, avgDelta)
	} else {
		println("Shuffle() 1 out of 1 tests passed.")
	}

}

//i, d, s

func circularDelta(a, b, c uint64) float64 {
	// computes the closest distance to the new position positions int the array
	// are a cyclic group defined by length
	i := int64(a)

	d := int64(b)

	s := int64(c)

	delta1 := math.Abs(float64(i - d))
	delta2 := float64((s - i) + d)
	delta3 := float64(i + (s - d))

	if delta1 < delta2 && delta1 < delta3 {
		return delta1
	} else if delta2 < delta1 && delta2 < delta3 {
		return delta2
	} else {
		return delta3
	}
}

// Test the shuffle on a list of length 1
func TestShuffleLen1(t *testing.T) {
	var testlst []uint64
	testlst = append(testlst, 1)
	Shuffle(&testlst)
}
