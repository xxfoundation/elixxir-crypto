package cyclic

import (
	"errors"
	"gitlab.com/elixxir/crypto/large"
)

// Store the same group fingerprint for multiple values
type IntBuffer struct {
	values      []*large.Int
	fingerprint uint64
}

func (i *IntBuffer) Get(index int) *Int {
	return &Int{i.values[index], i.fingerprint}
}

// Functions that write into the IntBuffer may return this error
var ErrFingerprintDoesntMatch = errors.New("Fingerprint doesn't match")

func (b *IntBuffer) Set(index int, newInt *Int) error {
	if newInt.fingerprint != b.fingerprint {
		return ErrFingerprintDoesntMatch
	}
	b.values[index] = newInt.value
	return nil
}

// Returns an error if the fingerprint doesn't match
func (b *IntBuffer) Append(newInt *Int) error {
	if newInt.fingerprint != b.fingerprint {
		return ErrFingerprintDoesntMatch
	}
	b.values = append(b.values, newInt.value)
	return nil
}

// Returns an error if the fingerprint doesn't match on any Int
// If any Int doesn't match, none of the ints will be appended
func (b *IntBuffer) AppendMany(newInts []*Int) error {
	startingLength := len(b.values)
	for i := range newInts {
		if newInts[i].fingerprint != b.fingerprint {
			// reset the slice to its starting length
            b.values = b.values[:startingLength]
			return ErrFingerprintDoesntMatch
		}
		b.values = append(b.values, newInts[i].value)
	}
	return nil
}
