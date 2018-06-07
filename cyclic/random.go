package cyclic

import (
	"crypto/rand"
	jww "github.com/spf13/jwalterweatherman"
	"io"
)

type Random struct {
	min    *Int
	max    *Int
	fmax   *Int
	one    *Int
	reader io.Reader
}

// The random range is inclusive of both the minimum and maximum boundaries of
// the random range
func (r *Random) recalculateRange() {
	r.fmax.Sub(r.max, r.min)
	r.fmax.Add(r.fmax, r.one)
}

// SetMin sets Minimum value for the lower boundary of the random range
func (r *Random) SetMin(newMin *Int) {
	r.min.Set(newMin)
	r.recalculateRange()
}

// SetMinFromInt64 sets Min value for the lower boundary of the random range (int 64 version)
func (r *Random) SetMinFromInt64(newMin int64) {
	r.min.SetInt64(newMin)
	r.recalculateRange()
}

// SetMax sets Max value for the upper boundary of the random range
func (r *Random) SetMax(newMax *Int) {
	r.max.Set(newMax)
	r.recalculateRange()
}

// SetMaxFromInt64 sets Max val for the upper boundary of the random range (int 64 version)
func (r *Random) SetMaxFromInt64(newMax int64) {
	r.max.SetInt64(newMax)
	r.recalculateRange()
}

// NewRandom initializes a new Random with min and max values
func NewRandom(min, max *Int) Random {
	fmax := NewInt(0)
	gen := Random{min, max, fmax.Sub(max, min), NewInt(1), rand.Reader}
	return gen
}

// Rand generates a random Int x, min <= x < max
func (gen *Random) Rand(x *Int) *Int {
	ran, err := rand.Int(gen.reader, gen.fmax.value)
	if err != nil {
		panic(err.Error())
	}
	x.value = ran
	x = x.Add(x, gen.min)
	return x
}

//TODO: Remove GenerateRandomKey
// GenerateRandomKey is a Crypto Random number generator that returns a key with a specified size (in bytes)
// This function reads 'size' cryptographically secure pseudorandom numbers from rand.Reader and writes them to a byte slice.
func GenerateRandomKey(size int) ([]byte, error) {
	jww.WARN.Printf("GenerateRandomKey() is deprecated, " +
		"use GenerateRandomBytes() instead")
	key := make([]byte, size)
	_, err := rand.Read(key)

	if err != nil {
		return nil, err
	}

	return key, nil
}

// GenerateRandomBytes is a Crypto Random number generator that returns a
// string of bytes with a specified size (in bytes)
// This function reads 'size' cryptographically secure pseudorandom numbers from rand.Reader and writes them to a byte slice.
func GenerateRandomBytes(size int) ([]byte, error) {

	return GenerateRandomKey(size)
}
