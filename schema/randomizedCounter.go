package schema

import (
	"errors"
	"gitlab.com/privategrity/crypto/cyclic"
	"gitlab.com/privategrity/crypto/hash"
)

const MIN_RNG int64 = 1

// Generates the next count in a randomized counter in a defined field
// H(field|counter + rand)
func GenerateNextCount(field []byte, counter []byte) (hashed []byte,
	outCounter []byte, err error) {
	// Creates a random number generator between 1 and half the length of the
	// counter.  Doing this every call waists memory and processor cycles,
	// but this is intended to be an infrequent operation.  Therefore, the
	// simplicity outweighs the performance loss
	maxRng := int64((1 << uint64(len(counter)*4)) - 1)
	rng := cyclic.NewRandom(cyclic.NewInt(MIN_RNG), cyclic.NewInt(maxRng))

	//Create a cyclic int version of the counter
	cyclicCounter := cyclic.NewIntFromBytes(counter)

	// increment the counter by a random value in half the bit space of the
	// counter
	cyclicCounter.Add(cyclicCounter, rng.Rand(cyclic.NewInt(0)))

	// Check if the counter has overflowed (meaning max count has been reached)
	// and return an error if that has occurred.
	if cyclicCounter.BitLen() > (len(counter) * 8) {
		hashed = filledByteSlice(len(field)+len(counter), 0x00)
		outCounter = filledByteSlice(len(counter), 0xff)
		err = errors.New("Max number of UserIDs generated")
		return
	}

	// creates a hash to use in generating the output.
	// regeneration is acceptable for the same reason as above.
	uidhasher, _ := hash.NewCMixHash()

	// writes the field and the counter state to the hash
	uidhasher.Write(field)
	uidhasher.Write(cyclicCounter.Bytes())

	//Reads from the hash,
	// only retaining the lenght of the field plus the length of the counter
	hashed = uidhasher.Sum(nil)[0 : len(field)+len(counter)]
	outCounter = cyclicCounter.LeftpadBytes(uint64(len(counter)))

	return
}

func filledByteSlice(len int, filler byte) []byte {
	slc := make([]byte, len)
	for indx, _ := range slc {
		slc[indx] = filler
	}
	return slc
}
