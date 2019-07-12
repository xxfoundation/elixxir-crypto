////////////////////////////////////////////////////////////////////////////////
// Copyright © 2019 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

// Implementation of the Fortuna construction as specified by Ferguson, Schneier and Kohno
// in 'Cryptography Engineering: Design Principles and Practical Applications'
// Link: https://www.schneier.com/academic/paperfiles/fortuna.pdf
package fastRNG

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	_ "crypto/sha256"
	"encoding/binary"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/csprng"
	"hash"
	"sync"
)

type StreamGenerator struct {
	streams        []*Stream
	waitingStreams chan *Stream
	maxStreams     uint
	numStreams     uint
	scalingFactor  uint
}

type Stream struct {
	streamGen *StreamGenerator
	//AESCtr     cipher.Stream
	entropyCnt  uint
	rng         csprng.Source
	source      []byte
	numStream   uint
	mut         sync.Mutex
	fortunaHash hash.Hash
}

// NewStreamGenerator creates a StreamGenerator object containing up to streamCount streams.
func NewStreamGenerator(scalingFactor uint, streamCount uint) *StreamGenerator {
	return &StreamGenerator{
		scalingFactor:  scalingFactor,
		waitingStreams: make(chan *Stream, streamCount),
		maxStreams:     streamCount,
		numStreams:     uint(0),
		streams:        make([]*Stream, 0, streamCount),
	}
}

//Create a new stream, having it point to the corresponding stream generator
//Also increment the amount of streams created in the stream generator
//Bookkeeping slice for streams made
func (sg *StreamGenerator) newStream() *Stream {
	if sg.numStreams == sg.maxStreams {
		jww.FATAL.Panicf("Attempting to create too many streams")
		return &Stream{}
	}
	tmpStream := &Stream{
		streamGen:   sg,
		numStream:   sg.numStreams,
		entropyCnt:  0,
		fortunaHash: crypto.SHA256.New(),
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
			retStream = sg.newStream()
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
func (s *Stream) Read(b []byte) int {
	s.mut.Lock()
	if len(b)%aes.BlockSize != 0 {
		jww.ERROR.Printf("Requested read length is not byte aligned!")
	}

	src := s.source //just a block? or the entire thing??
	var dst []byte
	//Initialze a counter and hash to be used in the core function
	counter := make([]byte, aes.BlockSize)
	count := uint64(0)

	for block := 0; block < len(b)/aes.BlockSize; block++ {
		count++
		binary.LittleEndian.PutUint64(counter, count)
		var extension []byte
		s.entropyCnt--
		//where is entropy cnt changed??
		count++
		binary.LittleEndian.PutUint64(counter, count)
		if s.entropyCnt == 0 {
			extension = make([]byte, aes.BlockSize)
			_, err := s.rng.Read(extension)
			if err != nil {
				jww.ERROR.Printf(err.Error())
			}
		}

		dst = b[block*aes.BlockSize : (block+1)*aes.BlockSize]

		Fortuna(src, dst, extension, s.fortunaHash, &counter)

		src = b[block*aes.BlockSize : (block+1)*aes.BlockSize]
	}

	copy(s.source,dst)

	//DO WE NEED THIS ANYMORE
	//Read from source
	if requiredRandomness := s.getEntropyNeeded(uint(len(b))); requiredRandomness != 0 {
		_, err := s.rng.Read(s.source[0:requiredRandomness])
		if err != nil {
			jww.ERROR.Printf(err.Error())
		}

		s.SetEntropyCount(uint(len(b)))
	}

	//Decrease the amount of entropy by how much we read, now that this is known
	s.entropyCnt -= uint(len(b))

	s.mut.Unlock()
	return len(b)
}

func Fortuna(src, dst, ext []byte, fortunaHash hash.Hash, counter *[]byte) {
	fortunaHash.Reset()
	fortunaHash.Write(src)
	fortunaHash.Write(ext)

	key := fortunaHash.Sum(nil)
	block, err := aes.NewCipher(key)
	if err != nil {
		jww.ERROR.Printf(err.Error())
	}
	//Make sure the key is the key size (32 bytes), panic otherwise
	if len(key) != 32 {
		jww.ERROR.Printf("The key is not the correct length (ie not 32 bytes)!")
	}
	iv := make([]byte, aes.BlockSize)
	streamCipher := cipher.NewCTR(block, iv)

	streamCipher.XORKeyStream(src, *counter)

}

// Sets the required randomness, ie the amount we will read from source by factoring in the amount of entropy we
// actually have and the sources of entropy we have.
func (s *Stream) getEntropyNeeded(requestLen uint) uint {
	//Such that the return value is never negative (requestedLen - entropyCnt) would be negative
	// if entropyCnt > requestedLen
	if s.entropyCnt >= requestLen {
		return 0
	}

	//The addition (scalingFactor - 1) ensures that the returned value is always a ceiling rather than a floor
	//as an integer. e.g ceiling(a/b) = (a+b-1)/b
	return (requestLen - s.entropyCnt + s.streamGen.scalingFactor - 1) / s.streamGen.scalingFactor
}

// Increases the entropy by a factor of the requestedLen
func (s *Stream) SetEntropyCount(requestedLen uint) {
	s.entropyCnt += requestedLen * s.streamGen.scalingFactor
}
