package cyclic

import (
	"fmt"
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

	sumDlta := float64(0)
	numElements := float64(batch * reps)

	halfBatch := float64(batch) / float64(2.0)

	for i := uint64(0); i < reps; i++ {

		for j := uint64(0); j < batch; j++ {

			newDlta := circularDelta(outInts[i][j], j, batch)
			newDlta /= halfBatch

			sumDlta += newDlta

		}

	}

	avgDlta := sumDlta / numElements

	if (avgDlta < min) || (avgDlta > max) {
		t.Errorf("Test of Shuffle failed, expected delta between: '%v' and '%v', got: '%v'",
			min, max, avgDlta)
	} else {
		fmt.Println("Shuffle() 1 out of 1 tests passed.\n")
	}

}

//i, d, s

func circularDelta(a, b, c uint64) float64 {
    // computes the closest distance to the new position positions int the array
    // are a cyclic group defined by length
	i := int64(a)

	d := int64(b)

	s := int64(c)

	dlt1 := math.Abs(float64(i - d))
	dlt2 := float64((s - i) + d)
	dlt3 := float64(i + (s - d))

	if dlt1 < dlt2 && dlt1 < dlt3 {
		return dlt1
	} else if dlt2 < dlt1 && dlt2 < dlt3 {
		return dlt2
	} else {
		return dlt3
	}
}
