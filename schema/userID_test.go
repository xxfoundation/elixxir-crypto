package schema

import (
	"math"
	"testing"
)

func TestGenerateNextUID(t *testing.T) {

	// Test normal operation returns different values with different sets of
	// counter inputs
	counters := []uint32{25, 25, 20000, 9999999}

	results := make(map[uint64]uint32)

	for _, cntr := range counters {
		id, newcounter, _ := GenerateNextUID(0, cntr)

		if newcounter == cntr {
			t.Errorf("Test of GenerateNextUID failed: output counter was"+
				" equal to input counter; input: %v, output: %v",
				cntr, newcounter)
		}

		results[id] = cntr
	}

	if len(results) != len(counters) {
		t.Errorf("Test of GenerateNextUID failed: corrent number of results"+
			" not detected: expected: %v, recieved: %v, map: %v",
			len(counters), len(results), results)
	}

	// Test the error case where counter is full

	inputctr := uint32(math.MaxUint32)

	id, newcounter, err := GenerateNextUID(0, inputctr)

	if err == nil {
		t.Errorf("Test of GenerateNextUID failed: did not return error when"+
			" counter was full. id: %v, counter: %v", id, newcounter)
	} else {
		if id != 0 {
			t.Errorf("Test of GenerateNextUID failed: did not properly"+
				" handle ID when coutner was full: Expected: 0, "+
				"Recieved: %v", id)
		}

		if newcounter != math.MaxUint32 {
			t.Errorf("Test of GenerateNextUID failed: incremented"+
				" counter when coutner was full; Expected: %v, Recieved: %v",
				math.MaxUint32, newcounter)
		}
	}
}
