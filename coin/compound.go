package coin

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

	return Compound(protoCompound), nil
}

// Returns the value of all coins in the compound
func (c Compound) Value() uint64 {
	dr, _ := DeserializeDenominationRegister(c[DenominationRegStart:DenominationRegEnd])
	return dr.Value()
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

	dr, _ := DeserializeDenominationRegister(ci[DenominationRegStart:DenominationRegEnd])

	coins := dr.GetDenominationList()

	for _, dnom := range coins {

		if dnom == 5 {
			break
		}

		h.Write([]byte{imgPostfix})
		imgPostfix++

		imgByte := h.Sum(nil)[:CoinLen]
		imgByte[CoinPrefixLoc] = ci[PrefixSourceLoc]
		imgByte[CoinDenominationLoc] = (imgByte[CoinDenominationLoc] & ^DenominationMask) | byte(dnom)

		var img Coin

		for i, b := range imgByte {
			img[i] = b
		}

		imgLst = append(imgLst, img)
	}

	return imgLst
}
