package coin

import (
	"testing"
)

func TestCoinPreimagesAndImages(t *testing.T) {
	numTestedCoins := 100

	preimageslice := make([]Preimage, numTestedCoins)
	var err error

	for i := 0; i < numTestedCoins; i++ {

		denomination := uint8(uint64(i) % 8)

		preimageslice[i], err = NewCoinPreimage(denomination)

		if err != nil {
			t.Errorf("NewCoinPreimage() failed: could not generate "+
				"coin preimage #%v: %s", i, err.Error())
		}

		dnm := uint8(preimageslice[i][CoinLen-1]) &^ DenominationMask
		if (dnm &^ DenominationMask) != denomination {

			t.Errorf("NewCoinPreimage() failed: appended denomination"+
				" incorrect: for coin %v: Expected: %v, Recieved: %v", i, denomination,
				dnm)
		}

	}

	for i := 0; i < (numTestedCoins - 1); i++ {

		denomination := uint8(i % 8)

		if preimageslice[i].GetDenomination() != denomination {
			t.Errorf("Preimage.GetDenomination("+
				") failed: appended denomination"+
				" incorrect: for coin %v: Expected: %v, Recieved: %v", i,
				denomination, preimageslice[i].GetDenomination())
		}

		if comparePreimages(preimageslice[i], preimageslice[i+1]) {
			t.Errorf("NewCoinPreimage() failed: preimage %v and %v "+
				"match: %v, %v", i, i+i, preimageslice[i], preimageslice[i+1])
		}
	}

	imageslice := make([]Image, numTestedCoins)

	for i := 0; i < numTestedCoins; i++ {
		denomination := uint8(i % 8)

		imageslice[i] = preimageslice[i].ComputeImage()

		if imageslice[i].GetDenomination() != denomination {
			t.Errorf("Image.GetDenomination("+
				") failed: appended denomination"+
				" incorrect: for coin %v: Expected: %v, Recieved: %v", i,
				denomination, imageslice[i].GetDenomination())
		}
	}

	for i := 0; i < (numTestedCoins - 1); i++ {
		if compareImages(imageslice[i], imageslice[i+1]) {
			t.Errorf("CoinPreimage.ComputeImage() failed: image %v and %v "+
				"match: %v, %v", i, i+i, imageslice[i], imageslice[i+1])
		}
	}

	for i := 0; i < numTestedCoins; i++ {
		if !imageslice[i].Verify(preimageslice[i]) {
			t.Errorf("CoinImage.ComputeImage("+
				") failed: image %v did not verify", i)
		}
	}

	for i := 0; i < numTestedCoins; i++ {
		if imageslice[i].Verify(preimageslice[numTestedCoins-i-1]) {
			t.Errorf("CoinImage.ComputeImage("+
				") failed: image %v and %v matched", i, numTestedCoins-i-1)
		}
	}
}

func comparePreimages(a, b Preimage) bool {
	for i := 0; i < CoinLen; i++ {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

func compareImages(a, b Image) bool {
	for i := 0; i < CoinLen; i++ {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
