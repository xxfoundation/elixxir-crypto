package coin

import (
	"crypto/sha256"
	"gitlab.com/privategrity/crypto/cyclic"
)

//TODO: Multi-frame messages so this can be increased in size, this is too small
const CoinLen = 7 //56 bit

type Preimage [CoinLen]byte
type Image [CoinLen]byte

// Returns a new valid preimage for a coin
func NewCoinPreimage() (Preimage, error) {
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

	return preimage, nil
}

//Computes and returns an image for a given preimage
func (cpi Preimage) ComputeImage() Image {
	//Hash the preimage
	h := sha256.New()
	h.Write(cpi[:])
	img := h.Sum(nil)[0:CoinLen]

	var image Image

	//Convert the preimage to an array
	for i, pi := range img {
		image[i] = pi
	}

	return image
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
