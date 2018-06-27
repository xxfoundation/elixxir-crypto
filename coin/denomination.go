package coin

import "errors"

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

//Returns the value of a denomination
func (d Denomination) Value() uint64 {
	return uint64(1 << d)
}
