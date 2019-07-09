////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////
package fastRNG

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"gitlab.com/elixxir/crypto/csprng"
	"io"
	"testing"
)

// Checking the functionality of appending the source
// using the Fortuna construction
func TestStreamRead(t *testing.T) {

	//A large byte array, of which you will read size from src byte array
	requestedBytes := make([]byte, 4125)

	/*Initialize everything needed for stream*/

	//Mock random source, of arbitrarily insufficient (small) size
	testSource := make([]byte, 7, 7)
	_, err := io.ReadFull(rand.Reader, testSource)
	if err != nil {
		panic(err.Error())
	}
	//Mock block cipher
	testKey := make([]byte, 32)
	testIV := make([]byte, aes.BlockSize)
	block, err := aes.NewCipher(testKey[:aes.BlockSize])
	if err != nil {
		panic(err)
	}
	ciph := cipher.NewCTR(block, testIV)
	//TODO: Replace with constructor after 2nd ticket is done
	//Initialize streamGenerator
	//sg := NewStreamGenerator(NewSystemRNG, scalingFactor 16, streamCount 2)
	//sg.src = testSource
	//sg.AESCtr = ciph
	//Wont need to set entropy count
	sg := &StreamGenerator{
		src:           testSource,
		entropyCnt:    24,
		scalingFactor: 16,
		AESCtr:        ciph,
		rng:           csprng.NewSystemRNG(),
	}

	//Initialize the stream with the generator
	stream := Stream{streamGen: sg}
	stream.Read(requestedBytes)

	if len(sg.src) < len(requestedBytes) || bytes.Compare(sg.src, testSource) == 0 {
		t.Errorf("Fortuna construction did not add randomness to the source")
	}
}

// Checking whether requiredRandomness returns zero when the entropyCount is less than the requestedLen
func TestRequiredRandomness_ReturnsZero(t *testing.T) {
	//Initialize a streamGenerator and stream
	sg := &StreamGenerator{
		entropyCnt:    24,
		scalingFactor: 16,
		rng:          csprng.NewSystemRNG(),
	}
	stream := Stream{streamGen: sg}
	//Try to read less that the amount of entropy
	var lessThanEntropy uint = 23
	requiredRandomness := stream.requiredRandomness(lessThanEntropy)
	//Since we are reading less than entropy, reqLen-entropy<0, in which case we return 0
	//This is tested
	if requiredRandomness != 0 {
		t.Errorf("Required randomness is not being calculated correctly")
	}

}

func TestRequiredRandomness_ReturnsNonZero(t *testing.T) {
	//Initialize a streamGenerator and stream
	sg := &StreamGenerator{
		entropyCnt:    24,
		scalingFactor: 16,
		rng:           csprng.NewSystemRNG(),
	}
	stream := Stream{streamGen: sg}
	//Try to read more that the amount of entropy
	var greaterThanEntropy uint = 25
	requiredRandomness := stream.requiredRandomness(greaterThanEntropy)
	if requiredRandomness == 0 {
		t.Errorf("Required randomness is not being calculated correctly")
	}
}

func TestStream_SetEntropyCount(t *testing.T) {
	sg := &StreamGenerator{
		entropyCnt:    24,
		scalingFactor: 16,
		rng:           csprng.NewSystemRNG(),
	}

	stream := Stream{streamGen: sg}
	stream.SetEntropyCount(2)
	var testVal uint = 24 + 2*16

	if sg.entropyCnt != testVal {
		t.Errorf("Entropy count not reset correctly")
	}
}
