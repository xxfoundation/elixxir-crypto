////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////
package csprng

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
	sg := &StreamGenerator{
		src:           testSource,
		entropyCnt:    24,
		scalingFactor: 16,
		AESCtr:        ciph,
		rng:           NewSystemRNG(),
	}

	//Initialize the stream with the generator
	stream := Stream{streamGen: sg}
	stream.Read(requestedBytes)

	if len(sg.src) < len(requestedBytes) || bytes.Compare(sg.src, testSource) == 0 {
		panic("Fortuna construction did not add randomness to the source")
	}
}

// Checking whether requiredRandomness returns zero when the entropyCount is less than the requestedLen
func TestRequiredRandomness_ReturnsZero(t *testing.T) {
	//Initialize a streamGenerator and stream
	sg := &StreamGenerator{
		entropyCnt:    24,
		scalingFactor: 16,
		rng:           NewSystemRNG(),
	}
	stream := Stream{streamGen: sg}
	//Try to read less that the amount of entropy
	var lessThanEntropy uint = 23
	requiredRandomness := stream.requiredRandomness(lessThanEntropy)

	if requiredRandomness != 0 {
		panic("Required randomness is not being calculated correctly")
	}

}

func TestRequiredRandomness_ReturnsNonZero(t *testing.T) {
	//Initialize a streamGenerator and stream
	sg := &StreamGenerator{
		entropyCnt:    24,
		scalingFactor: 16,
		rng:           NewSystemRNG(),
	}
	stream := Stream{streamGen: sg}
	//Try to read less that the amount of entropy
	var greaterThanEntropy uint = 25
	requiredRandomness := stream.requiredRandomness(greaterThanEntropy)
	if requiredRandomness == 0 {
		panic("Required randomness is not being calculated correctly")
	}

}
