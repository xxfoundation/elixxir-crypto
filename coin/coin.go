package coin

import (
	"crypto/sha256"
	"errors"
	"gitlab.com/privategrity/crypto/cyclic"
	"gitlab.com/privategrity/crypto/format"
)

// A Seed contains the secret proving ownership of a series of coins
type Seed [CompoundLen]byte

// A Compound contains the intermediate hash describing a series of coins
type Compound [CompoundLen]byte

// An individual coin in the system
type Coin [CoinLen]byte

// Length of the base random number and its hashes
const HashLenBits = uint64(160)
const HashLen = HashLenBits / 8

// Calculates the number of coins in a compound based upon external data
const NumCompoundsPerPayload = uint64(5)
const MaxCoinsPerCompound = DenominationPerByte * ((format.DATA_LEN / NumCompoundsPerPayload) - HashLen)
const CompoundLen = HashLen + MaxCoinsPerCompound/2

// Defines the size of a coin
const CoinLen = HashLen + 1

// Returnable errors
var ErrZeroCoins = errors.New("no denominations passed")
var ErrExcessiveCoins = errors.New("too many denominations passed")

// Creates a new randomized seed defining coins of the passed denominations
func NewSeed(denominations []Denomination) (Seed, error) {

	// Check that denominations were passed
	if len(denominations) == 0 {
		return Seed{}, ErrZeroCoins
	}

	// Make sure that the number of subcoins does not exceed the maximum
	if uint64(len(denominations)) > MaxCoinsPerCompound {
		return Seed{}, ErrExcessiveCoins
	}

	// Check the denominations are valid
	for _, denom := range denominations {
		if denom >= NumDenominations {
			return Seed{}, ErrInvalidDenomination
		}
	}

	//Generate the seed
	p, err := cyclic.GenerateRandomBytes(int(CompoundLen))
	if err != nil {
		return Seed{}, err
	}

	var seed Seed

	//Convert the image to an array
	for i, pi := range p {
		seed[i] = pi
	}

	//Append Nil Denominations to the Denomination List
	for i := uint64(len(denominations)); i < MaxCoinsPerCompound; i++ {
		denominations = append(denominations, NilDenomination)
	}

	//Append the denominations to the coin
	for i := uint64(0); i < (CompoundLen - HashLen); i++ {
		seed[HashLen+i] = byte(denominations[2*i]<<4 | denominations[2*i+1])
	}

	return seed, nil
}

// Returns a list of the denominations of all coins defined in the seed
func (cpi Seed) GetCoins() []Denomination {
	return getCoins(cpi)
}

// Returns the Number of coins defined by a seed
func (cpi Seed) GetNumCoins() uint64 {
	return getNumCoins(cpi)
}

// Returns the value of all coins defined by a seed
func (cpi Seed) Value() uint64 {
	return value(cpi)
}

//Computes and returns a compound for a given seed
func (cpi Seed) ComputeCompound() Compound {
	//Hash the preimage
	h := sha256.New()
	h.Write(cpi[:])
	img := h.Sum(nil)[0:CompoundLen]

	var image Compound

	//Convert the preimage to an array
	for i, pi := range img {
		image[i] = pi
	}

	//Copy the denominations over from the coin
	for i := HashLen; i < CompoundLen; i++ {
		image[i] = cpi[i]
	}

	return image
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

// Returns all coins defined by a compound
func (ci Compound) ComputeCoins() []Coin {
	imgPostfix := byte(0)
	var imgLst []Coin

	h := sha256.New()

	cibytes := ci[:]

	h.Write(cibytes)

	for _, dnom := range ci.GetCoins() {

		if dnom == NilDenomination {
			break
		}

		h.Write([]byte{imgPostfix})
		imgPostfix++
		imgByte := h.Sum(nil)[0:HashLen]
		imgByte[HashLen] = (imgByte[HashLen] & 0xF0) | byte(dnom)

		var img Coin

		for i, b := range imgByte {
			img[i] = b
		}

		imgLst = append(imgLst, img)
	}

	return imgLst
}

//Verify that a compound matches a seed
func (cimg Compound) Verify(preimage Seed) bool {
	computedImage := preimage.ComputeCompound()

	for i := uint64(0); i < CompoundLen; i++ {
		if computedImage[i] != cimg[i] {
			return false
		}
	}

	return true
}

// Internal function used by both seed and compound to return all Coins
func getCoins(pi [CompoundLen]byte) []Denomination {
	var denom []Denomination
	for i := HashLen; i < CompoundLen; i++ {
		denom1 := Denomination((pi[i] >> 4) & 0x0f)

		if denom1 >= NilDenomination {
			break
		}

		denom = append(denom, denom1)

		denom2 := Denomination(pi[i] & 0x0f)
		if denom2 >= NilDenomination {
			break
		}

		denom = append(denom, denom2)
	}

	return denom
}

// Internal function used by both seed and compound to return the number of
// Coins
func getNumCoins(pi [CompoundLen]byte) uint64 {
	numDenom := uint64(0)
	for i := HashLen; i < CompoundLen; i++ {
		denom1 := Denomination((pi[i] >> 4) & 0x0f)

		if denom1 >= NilDenomination {
			break
		}

		numDenom++

		denom2 := Denomination(pi[i] & 0x0f)

		if denom2 >= NilDenomination {
			break
		}

		numDenom++
	}
	return numDenom
}

// Internal function used by both seed and compound to return the sum of
// the value of all coins represented
func value(pi [CompoundLen]byte) uint64 {
	v := uint64(0)
	for _, dnm := range getCoins(pi) {
		v += dnm.Value()
	}
	return v
}
