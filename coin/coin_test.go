package coin

import "testing"

func TestCoinPreimagesAndImages(t *testing.T) {
	numTestedCoins := 100

	preimageslice := make([]Preimage, numTestedCoins)
	var err error

	for i := 0; i < numTestedCoins; i++ {
		preimageslice[i], err = NewCoinPreimage()

		if err != nil {
			t.Errorf("NewCoinPreimage() failed: could not generate "+
				"coin preimage #%v: %s", i, err.Error())
		}
	}

	for i := 0; i < (numTestedCoins - 1); i++ {
		if comparePreimages(preimageslice[i], preimageslice[i+1]) {
			t.Errorf("NewCoinPreimage() failed: preimage %v and %v "+
				"match: %v, %v", i, i+i, preimageslice[i], preimageslice[i+1])
		}
	}

	imageslice := make([]Image, numTestedCoins)

	for i := 0; i < numTestedCoins; i++ {
		imageslice[i] = preimageslice[i].ComputeImage()
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
