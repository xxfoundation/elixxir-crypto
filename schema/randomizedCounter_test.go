package schema

import (
	"gitlab.com/privategrity/crypto/cyclic"
	"testing"
)

func TestGenerateNextCount(t *testing.T) {

	// Test normal operation returns different values with different sets of
	// counter inputs
	counters := [][]byte{cyclic.NewInt(25).LeftpadBytes(5),
		cyclic.NewInt(25).LeftpadBytes(8),
		cyclic.NewInt(25).LeftpadBytes(8),
		cyclic.NewInt(40000).LeftpadBytes(10),
		cyclic.NewInt(3333333).LeftpadBytes(11),
	}

	results := make(map[string]string)

	for _, cntr := range counters {
		hash, newcounter, _ := GenerateNextCount(
			cyclic.NewInt(0).LeftpadBytes(10),
			cntr)

		if cyclic.NewIntFromBytes(newcounter).Text(16) == cyclic.NewIntFromBytes(cntr).Text(16) {
			t.Errorf("Test of GenerateNextUID failed: output counter was"+
				" equal to input counter; input: %v, output: %v",
				cyclic.NewIntFromBytes(newcounter).Text(16), cyclic.NewIntFromBytes(cntr).Text(16))
		}

		results[cyclic.NewIntFromBytes(hash).Text(16)] =
			cyclic.NewIntFromBytes(newcounter).Text(16)
	}

	if len(results) != len(counters) {
		t.Errorf("Test of GenerateNextUID failed: corrent number of results"+
			" not detected: expected: %v, recieved: %v, map: %v",
			len(counters), len(results), results)
	}

	// Test the error case where counter is full

	hash, newcounter, err := GenerateNextCount(
		cyclic.NewInt(0).LeftpadBytes(10),
		cyclic.NewInt((1<<32)-1).LeftpadBytes(4))

	if err == nil {
		t.Errorf("Test of GenerateNextUID failed: did not return error when"+
			" counter was full. id: %v, counter: %v",
			cyclic.NewIntFromBytes(hash).Int64(), newcounter)
	} else {
		if cyclic.NewIntFromBytes(hash).Int64() != 0 {
			t.Errorf("Test of GenerateNextUID failed: did not properly"+
				" handle ID when coutner was full: Expected: 0, "+
				"Recieved: %v", cyclic.NewIntFromBytes(hash).Int64())
		}

		if cyclic.NewIntFromBytes(newcounter).Int64() != ((1 << 32) - 1) {
			t.Errorf("Test of GenerateNextUID failed: incremented"+
				" counter when coutner was full; Expected: %v, Recieved: %v",
				((1 << 32) - 1), cyclic.NewIntFromBytes(newcounter).Int64())
		}
	}
}
