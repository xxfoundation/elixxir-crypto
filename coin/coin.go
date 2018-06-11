package coin

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"gitlab.com/privategrity/crypto/cyclic"
)

//TODO: Multi-frame messages so this can be increased in size, this is too small
const CoinLen = 7 //56 bit
const Denominations = uint8(8)
const DenominationMask = uint8(0xF8)

type Preimage [CoinLen]byte
type Image [CoinLen]byte

func NewCoinPreimage(denomination uint8) (Preimage, error) {

	//Check the denomination
	if denomination >= Denominations {
		return Preimage{}, errors.New(fmt.Sprintf(
			"invalid denomination recieved: %v", denomination))
	}

	//Generate the image
	p, err := cyclic.GenerateRandomBytes(CoinLen)
	if err != nil {
		return Preimage{}, err
	}

	var preimage Preimage

	//Convert the image to an array
	for i, pi := range p {
		preimage[i] = pi
	}

	//Append the denomination to the last 3 bits of the image
	preimage[CoinLen-1] = (preimage[CoinLen-1] & DenominationMask) | denomination

	return preimage, nil
}

//Computes and returns an image for a given preimage
func (cpi Preimage) ComputeImage() Image {
	//Store the images denomination

	//Hash the preimage
	h := sha256.New()
	h.Write(cpi[:])
	img := h.Sum(nil)[0:CoinLen]

	var image Image

	//Convert the preimage to an array
	for i, pi := range img {
		image[i] = pi
	}

	image[CoinLen-1] = (image[CoinLen-1] & DenominationMask) | cpi[CoinLen-1]

	return image
}

func (cpi Preimage) GetDenomination() uint8 {
	return cpi[CoinLen-1] &^ DenominationMask
}

//Verify the an ImagePreimage Pair
func (img Image) Verify(preimage Preimage) bool {
	computedImage := preimage.ComputeImage()

	for i := 0; i < CoinLen; i++ {
		if computedImage[i] != img[i] {
			return false
		}
	}

	return true
}

func (img Image) GetDenomination() uint8 {
	return img[CoinLen-1] &^ DenominationMask
}
