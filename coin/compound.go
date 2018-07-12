package coin

/*
import "crypto/sha256"

// A Compound contains the intermediate hash describing a series of coins
type Compound [BaseFrameLen]byte

//Compound Header
const CompoundType byte = 0xAA

// Produces a compound serialized from an array.
func DeserializeCompound(protoCompound [BaseFrameLen]byte) (Compound, error) {
	//Check that the header is correct
	if protoCompound[HeaderLoc] != CompoundType {
		return Compound{}, ErrInvalidType
	}

	//Check that the denomination list is valid
	if err := checkDenominationList(getCoins(protoCompound)); err != nil {
		return Compound{}, err
	}

	return Compound(protoCompound), nil
}

// Returns a list of the denominations of all coins defined in the Compound
func (ci Compound) GetCoins() []Denomination {
	return getCoins(ci)
}

// Returns the number of coins defined by the compound
func (ci Compound) GetNumCoins() uint64 {
	return getNumCoins(ci)
}

// Returns the value of all coins in the compound
func (ci Compound) Value() uint64 {
	return value(ci)
}

//Verify that a compound matches a seed
func (cimg Compound) Verify(seed Seed) bool {
	computedImage := seed.ComputeCompound()

	for i := uint64(0); i < BaseFrameLen; i++ {
		if computedImage[i] != cimg[i] {
			return false
		}
	}

	return true
}

// Returns all coins defined by a compound
func (ci Compound) ComputeCoins() []Coin {
	imgPostfix := byte(0)
	var imgLst []Coin

	h := sha256.New()

	cibytes := ci[HashStart:HashEnd]

	h.Write(cibytes)

	for _, dnom := range ci.GetCoins() {

		if dnom == 5 {
			break
		}

		h.Write([]byte{imgPostfix})
		imgPostfix++

		imgByte := h.Sum(nil)[:CoinLen]
		imgByte[CoinDenominationLoc] = (imgByte[CoinDenominationLoc] & 0xf0) | byte(dnom)

		var img Coin

		for i, b := range imgByte {
			img[i] = b
		}

		imgLst = append(imgLst, img)
	}

	return imgLst
}*/
