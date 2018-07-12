package coin

import "errors"

//Defines the properties of Deonominations
const NumDenominations = uint64(24)

const MaxValueDenominationRegister = uint64(1<<NumDenominations - 1)
const DenominationRegisterLen = NumDenominations / 8

// The denomination of a coin.
// The value of the coin is 2^Denomination and the only valid denominations
// are 0, 1, 2, 3, .... , 22, and 23
type Denomination uint8

// Error returned if a denomination is valid
var ErrInvalidDenomination = errors.New("A passed denomination is not valid")
var ErrInvalidValue = errors.New("A passed value cannot be represented in a single DenominationList")

//Returns the value of a denomination
func (d Denomination) Value() uint32 {
	return uint32(1 << d)
}

//List of denominations appended to a compound or seed
type DenominationRegister [DenominationRegisterLen]byte

func NewDenominationRegister(value uint64) (DenominationRegister, error) {
	if value > MaxValueDenominationRegister {
		return DenominationRegister{}, ErrInvalidValue
	}

	if value == 0 {
		return DenominationRegister{}, ErrInvalidValue
	}

	var ndr DenominationRegister

	for i := uint64(0); i < DenominationRegisterLen; i++ {
		ndr[i] = byte((value >> (i * 8)) & 0x00ff)
	}

	return ndr, nil
}

func (dl DenominationRegister) BitState(bit uint8) bool {
	return ((dl[bit/8] >> (bit % 8)) & 0x01) == 1
}

func (dl DenominationRegister) GetDenominationList() []Denomination {
	var denomoinationList []Denomination

	for i := uint64(0); i < NumDenominations; i++ {
		if dl.BitState(uint8(i)) {
			denomoinationList = append(denomoinationList, Denomination(1<<uint16(i)))
		}
	}

	return denomoinationList
}

func (dl DenominationRegister) Value() uint64 {
	value := uint64(0)

	for i := uint64(0); i < DenominationRegisterLen; i++ {
		value = value | uint64(dl[i]<<(i*8))
	}

	return value
}
