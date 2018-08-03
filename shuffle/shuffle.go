package cyclic

import (
	"crypto/sha256"
	"encoding/binary"
	"math/rand"
)

// Shuffles anything passed using a Fisher-Yates shuffle backed by a PRNG seeded by a passed slice
// Swap functions must be of the form `A[i], A[j] = A[j], A[i]`
// Switching i and j may not work
func ShufflePRNG(seedSrc []byte, n int, swap func(i, j int)) {
	// Skip empty lists or lists of only 1 element, they cannot be shuffled
	if n <= 1 {
		return
	}

	//Generate the seed
	h := sha256.New()
	h.Write(seedSrc)

	seed := h.Sum(nil)

	//Seed the PRNG
	src := rand.NewSource(int64(binary.BigEndian.Uint64(seed[0:8]) >> 1))
	prng := rand.New(src)

	for curPos := int64(0); curPos < int64(n)-1; curPos++ {
		// Shuffle should be able to swap with any element that hasn't
		// already been shuffled

		randPos := prng.Int63n(int64(n)-curPos) + curPos

		swap(int(curPos), int(randPos))
	}
}
