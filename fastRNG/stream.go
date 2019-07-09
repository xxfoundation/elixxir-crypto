////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

// Implementation of the Fortuna construction as specified by Feruson, Schnier and Kohno
// in 'Cryptography Engineering: Design Principles and Practical Applications'
// Link: https://www.schneier.com/academic/paperfiles/fortuna.pdf
package fastRNG

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	jww "github.com/spf13/jwalterweatherman/jwalterweatherman"
	"gitlab.com/elixxir/crypto/csprng"
	"go.uber.org/atomic"
	"sync"
)

//Global hashing variable, used in the Fortuna construction
var newHash = sha256.New()

type StreamGenerator struct {
	AESCtr         cipher.Stream
	scalingFactor  uint
	entropyCnt     uint
	rng            csprng.Source
	src            []byte
	streams        []*Stream
	waitingStreams chan *Stream
	maxStreams     uint
	order          []uint64
	numStreams     uint
}

type Stream struct {
	streamGen *StreamGenerator
	mutex     sync.Mutex
	isBusy    atomic.Bool //throw mutex around changing value to make thread-safe
	numStream uint
}

// NewStreamGenerator creates a StreamGenerator object containing up to streamCount streams.
func NewStreamGenerator(source csprng.Source, scalingFactor uint, streamCount uint) *StreamGenerator {
	//Initialize an order to shuffle indexes in waiting streams
	//NOTE: We do this because we do not want to redo the shuffle algorithm. It would (probably) be more
	//efficient, but it would come down to reiterating code and having to manage two code sources doing the same thing
	randIndex := make([]uint64, streamCount)
	for i := uint(0); i < streamCount; i++ {
		randIndex[i] = uint64(i)
	}
	return &StreamGenerator{
		rng:            source,
		scalingFactor:  scalingFactor,
		entropyCnt:     20, //Some default value for our use?
		waitingStreams: make(chan *Stream, streamCount),
		maxStreams:     streamCount,
		order:          randIndex,
		numStreams:     uint(0),
		streams:        make([]*Stream, 0, streamCount),
	}
}

//Create a new stream, having it point to the corresponding stream generator
//Also increment the amount of streams created in the stream generator
//Bookkeeping slice for streams made
func (sg *StreamGenerator) NewStream() *Stream {
	if sg.numStreams == sg.maxStreams {
		panic("Attempting to create too many streams")
	}
	tmpStream := &Stream{
		streamGen: sg,
		numStream: sg.numStreams,
	}
	sg.streams = append(sg.streams, tmpStream)
	sg.numStreams++
	return tmpStream
}

// GetStream gets an existing stream or creates a new Stream object. If the # of open streams exceeds streamCount,
// this function blocks (and prints a log warning) until a stream is available
func (sg *StreamGenerator) GetStream() *Stream {
	//Initialize a stream
	var retStream *Stream
	//If there is a stream waiting to be used, take that from the channel and return in
	select {
	case retStream = <-sg.waitingStreams:
	default:

	}

	//If there was no waiting channels, ie we exited the select statement
	if retStream == nil {
		//If we have not reached the maximum amount of streams (specified by streamCount), then create a new one
		if sg.numStreams < sg.maxStreams {
			retStream = sg.NewStream()
		} else {
			//Else block until a stream is put in the waiting channel
			retStream = <-sg.waitingStreams
		}
	}
	return retStream
}

// Close closes the stream object, locking it from external users and marking it as available in the stream list
func (sg *StreamGenerator) Close(stream *Stream) {
	sg.waitingStreams <- stream
}

// Read reads up to len(b) bytes from the csprng.Source object. This function panics if the stream is locked.
// Users of stream objects should close them when they are finished using them. We read the AES256
// blocksize into AES then run it until blockSize*scalingFactor bytes are read. Every time
// blocksize*scalingFactor bytes are read this functions blocks until it rereads csprng.Source.
// TODO: Add 'blocking' logic, which is blocked by the ticket currently described above
func (s *Stream) Read(b []byte) int {
	//If the requested buffer exceeds the randomness generated thus far, then append until we have enough
	if len(b) > len(s.streamGen.src) {
		s.AppendSource(len(b))
	}

	//Read from source
	if requiredRandomness := s.requiredRandomness(uint(len(b))); requiredRandomness != 0 {
		_, err := s.streamGen.rng.Read(s.streamGen.src[0:requiredRandomness])
		if err != nil {
			jww.ERROR.Printf(err.Error())
		}
		//
		s.SetEntropyCount(uint(len(b)))
	}

	//
	s.streamGen.entropyCnt -= uint(len(b))
	//Make 'new randomness' by changing the stale values (already read data read through xor'ring
	//We may also just as easily retire the read values. This is up to discussion?
	s.streamGen.AESCtr.XORKeyStream(s.streamGen.src[:len(b)], b)

	return len(b)
}

// If the source is not large for the amount to be read in, extend the source
// using the Fortuna construction. Need a new block IV every
// In usage, src will initially pull from Linux's rng
func (s *Stream) AppendSource(lenToApp int) {
	//Initialize key and block
	key := make([]byte, 0)
	seedArr := append(key, s.streamGen.src...)
	key = newHash.Sum(seedArr)

	block, err := aes.NewCipher(key[:aes.BlockSize])
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, aes.BlockSize+len(key))
	var temp uint32 = 0
	counter := make([]byte, aes.BlockSize)
	for len(s.streamGen.src) < lenToApp {
		//Encrypt the key and counter, inc ctr for next round of generation
		binary.LittleEndian.PutUint32(counter, temp)
		stream := cipher.NewCTR(block, counter)
		stream.XORKeyStream(ciphertext[aes.BlockSize:], key)
		//So there is no predictable iv appended to the random src
		tmp := ciphertext[aes.BlockSize:]
		s.streamGen.src = append(s.streamGen.src, tmp...)
		temp++
	}
}

// TODO: test this function
// Sets the required randomness, ie the amount we will read from source by factoring in the amount of entropy we
// actually have and the sources of entropy we have. Definitions:

func (s *Stream) requiredRandomness(requestLen uint) uint {
	//Such that (requestLen - entropyCnt is never negative
	if s.streamGen.entropyCnt < requestLen {
		//The addition (scalingFactor - 1) ensures that the returned value is always a ceiling rather than a floor
		//as an integer. e.g ceiling(a/b) = (a+b-1)/b
		return (requestLen - s.streamGen.entropyCnt + s.streamGen.scalingFactor - 1) / s.streamGen.scalingFactor
	}
	return 0
}

// Increases the entryopy
func (s *Stream) SetEntropyCount(requestedLen uint) {
	s.streamGen.entropyCnt += requestedLen * s.streamGen.scalingFactor
}
