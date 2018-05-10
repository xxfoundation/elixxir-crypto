package schema

import (
	"encoding/binary"
	"errors"
	"fmt"
	"gitlab.com/privategrity/crypto/cyclic"
	"gitlab.com/privategrity/crypto/hash"
	"math"
)

const MIN_RNG int64 = 1
const MAX_RNG int64 = math.MaxUint16

// Generates the next userID in the series,
// returning it and the updated counter.
func GenerateNextUID(nodeid, counter uint32) (uint64, uint32, error) {
	// creates a random number generator between 1 and 2^16-1 for incrementing
	// the counter.  Doing this every time waists memory and processor
	// cycles, but this is an infrequent enough operation that the downsides
	// are outweighed by the increase simplicity in the interface
	rng := cyclic.NewRandom(cyclic.NewInt(MIN_RNG), cyclic.NewInt(MAX_RNG))

	oldCounter := counter

	// increment the counter by a random value in the 2^16 space
	counter += uint32(rng.Rand(cyclic.NewInt(0)).Uint64())

	// Check if the counter has overflowed (meaning max users has been reached)
	// and return an error if that has occurred.
	if counter < oldCounter {
		return 0, math.MaxUint32, errors.New("Max number of UserIDs generated")
	}

	// creates a hash to use in generating the userID.
	// regeneration is acceptable for the same reason as above.
	uidhasher, _ := hash.NewCMixHash()

	// writes the node id and the counter state to the hash
	uidhasher.Write(convertUint32toByteSlice(nodeid))
	uidhasher.Write(convertUint32toByteSlice(counter))

	//Reads from the hash, only retaining 64 bits
	uidhash := uidhasher.Sum(nil)[0:8]

	return binary.BigEndian.Uint64(uidhash), counter, nil
}

func convertUint32toByteSlice(u uint32) []byte {
	a := make([]byte, 4)
	binary.BigEndian.PutUint32(a, u)
	return a
}
