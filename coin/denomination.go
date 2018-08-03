package coin

import (
	"errors"
)

//Defines the properties of Denominations
const NumDenominations = uint64(24)

const MaxValueDenominationRegister = uint64(1<<NumDenominations - 1)
const DenominationRegisterLen = NumDenominations / 8

// The denomination of a coin.
// The value of the coin is 2^Denomination and the only valid denominations
// are 0, 1, 2, 3, .... , 22, and 23
type Denomination uint8

// Error returned if a denomination is valid
var ErrInvalidValue = errors.New("A passed value cannot be represented in a single DenominationList")
var ErrIncorrectLen = errors.New("A slice passed is the wrong length")

//Returns the value of a denomination
func (d Denomination) Value() uint64 {
	return uint64(1 << d)
}

//List of denominations appended to a compound or seed
type DenominationRegister []byte

//Creates a new denomination register
func NewDenominationRegistry(protoregister []byte, value uint64) (DenominationRegister, error) {
	// Checked that the passed slice is the correct length
	if uint64(len(protoregister)) != DenominationRegisterLen {
		return DenominationRegister{}, ErrIncorrectLen
	}

	// Make sure the passed value isnt larger than a denomination register can hold
	if value > MaxValueDenominationRegister {
		return DenominationRegister{}, ErrInvalidValue
	}

	// Compound Coins cant hold a value of zero
	if value == 0 {
		return DenominationRegister{}, ErrInvalidValue
	}

	// Load the value into the slice
	for i := uint64(0); i < DenominationRegisterLen; i++ {
		protoregister[i] = byte(value >> (8 * i) & 0xff)
	}

	return DenominationRegister(protoregister), nil
}

// Creates a DenominationRegistry from a slice of the appropriate length
func DeserializeDenominationRegistry(protoregister []byte) (DenominationRegister, error) {
	// check that the slice is the correct length
	if uint64(len(protoregister)) != DenominationRegisterLen {
		return DenominationRegister{}, ErrIncorrectLen
	}

	return DenominationRegister(protoregister), nil
}

// Returns the value of a specific bit in the DenominationRegistry
func (dl DenominationRegister) BitState(bit uint8) bool {
	return ((dl[bit/8] >> (bit % 8)) & 0x01) == 1
}

// Returns a list of all denominations represented by the DenominationRegistry
func (dl DenominationRegister) List() []Denomination {
	var denomoinationList []Denomination

	for i := uint64(0); i < NumDenominations; i++ {
		if dl.BitState(uint8(i)) {
			denomoinationList = append(denomoinationList, Denomination(i))
		}
	}

	return denomoinationList
}

// Returns the overall value of the coins represented by the DenominationRegistry
func (dl DenominationRegister) Value() uint64 {
	value := uint64(0)

	for i := uint64(0); i < DenominationRegisterLen; i++ {
		value = value | uint64(dl[i])<<(i*8)
	}

	return value
}
