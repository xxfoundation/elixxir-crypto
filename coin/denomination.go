package coin

import (
	"errors"
)

//Defines the properties of Deonominations
const NumDenominations = Denomination(15)
const NilDenomination = Denomination(0x0f)
const DenominationPerByte = uint64(2)

// The denomination of a coin.
// The value of the coin is 2^Denomination and the only valid denominations
// are 0, 1, 2, 3, .... , 13, and 14
type Denomination uint8

// Error returned if a denomination is valid
var ErrInvalidDenomination = errors.New("A passed denomination is not valid")
var ErrInvalidValue = errors.New("value too large to be converted to a denomination list")

//Returns the value of a denomination
func (d Denomination) Value() uint64 {
	return uint64(1 << d)
}

//Generates a list of denominations
func GenerateDenominationList(value uint32) ([]Denomination, error) {

	var dl []Denomination

	if value > (1<<15)-1 {
		return []Denomination{}, ErrInvalidValue
	}

	for i := uint32(0); i < uint32(MaxCoinsPerCompound); i++ {
		if (value>>i)&0x0001 == 1 {
			dl = append(dl, Denomination(i))
		}
	}

	return dl, nil

}
