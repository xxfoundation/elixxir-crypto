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

//Checking the functionality of appending the source
//using the Fortuna construction
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

func TestStreamReadReturnsZero(t *testing.T)  {

}