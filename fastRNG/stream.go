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
	"fmt"
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
	streamGen  *StreamGenerator
	//AESCtr     cipher.Stream
	entropyCnt uint
	rng        csprng.Source
	source     []byte
	numStream  uint
	mut        sync.Mutex
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
		streamGen:  sg,
		numStream:  sg.numStreams,
		entropyCnt: 0,
		fortunaHash:crypto.SHA256.New(),
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
	if len(b)%aes.BlockSize!=0 {
		jww.ERROR.Printf("Requested read length is not byte aligned!")
	}

	src := s.source //just a block? or the entire thing??
	var dst []byte
	i := 0
	//Initialize indexers to use as block start & end positions
	startOfBlock := i * 16
	endOfBlock := (i + 1) * 16
	//Initialze a counter and hash to be used in the core function
	counter := make([]byte,aes.BlockSize)
	count := uint64(0)
	for block:=0;block<len(b)/aes.BlockSize;block++ {
		count++
		binary.LittleEndian.PutUint16(counter, count)
		var extension []byte
		s.entropyCnt--
		//where is entropy cnt changed??

		if s.entropyCnt == 0 {
			extension = make([]byte, aes.BlockSize)
			_, err := s.rng.Read(extension)
			if err != nil {
				jww.ERROR.Printf(err.Error())
			}
		}
	}
	//for numBlock := 0; numBlock < len(s.src)/aes.BlockSize; numBlock++ {
	//src := s.src[numBlock*aes.BlockSize:(numBlock+1)*aes.BlockSize]
	s.fortuna(b)
	//}

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

	//Make 'new randomness' by changing the stale values (already read data read through xor'ring
	//We may also just as easily retire the read values. This is up to discussion?
	s.AESCtr.XORKeyStream(s.source[:len(b)], b)
	s.mut.Unlock()
	return len(b)
}

func (s *Stream) fortuna(b []byte) { //, src []byte) {
	src := s.source //just a block? or the entire thing??
	var dst []byte
	i := 0
	//Initialize indexers to use as block start & end positions
	startOfBlock := i * 16
	endOfBlock := (i + 1) * 16
	//Initialze a counter and hash to be used in the core function
	hash := crypto.SHA256
	counter := make([]byte, aes.BlockSize)
	count := uint16(0)
	//Go until you have reached the end
	for endOfBlock < len(b) {
		count++
		binary.LittleEndian.PutUint16(counter, count)
		var extension []byte
		s.entropyCnt--
		//where is entropy cnt changed??

		if s.entropyCnt == 0 {
			extension = make([]byte, aes.BlockSize)
			_, _ = s.rng.Read(extension)
		}
		dst = b[startOfBlock:endOfBlock]

		fortunaCore(src, dst, hash, &counter, extension)
		src = b[startOfBlock:endOfBlock]
		startOfBlock = i * aes.BlockSize
		endOfBlock = (i + 1) * aes.BlockSize
		i++

	}
	if startOfBlock > len(b) {
		startOfBlock = len(b) - 1
	}
	endOfBlock = len(b) - 1
	copy(s.source, b[startOfBlock:endOfBlock])
}

func fortunaCore(src []byte, dst []byte, hash crypto.Hash, ctr *[]byte, ext []byte) {
	fortunaHash := hash.New()
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
	streamCipher := cipher.NewCTR(block, *ctr)

	streamCipher.XORKeyStream(src, *ctr)

}

// If the source is not large for the amount to be read in, extend the source
// using the Fortuna construction. In usage, src will initially pull from Linux's rng
func (s *Stream) extendSource(extensionLen int) {
	//Initialize key and block
	fortunaHash := crypto.SHA256.New()
	key := fortunaHash.Sum(s.source)

	key = key[len(s.source):]
	fmt.Println(key)
	block, err := aes.NewCipher(key[:aes.BlockSize])
	if err != nil {
		jww.ERROR.Printf(err.Error())
	}
	//Make sure the key is the key size (32 bytes), panic otherwise
	if len(key) != 32 {
		jww.ERROR.Printf("The key is not the correct length (ie not 32 bytes)!")
	}
	aesRngBuf := make([]byte, aes.BlockSize+len(key))
	var count uint16 = 0
	counter := make([]byte, aes.BlockSize)
	streamCipher := cipher.NewCTR(block, counter)

	//Encrypt the key and counter, inc ctr for next round of generation
	for len(s.source) < extensionLen {
		//Increment the temp, place in the counter. When the temp var overflows, the 1 is carried over to the next byte
		//in counter, treating it like a binary number. Counter is used as the IV
		binary.LittleEndian.PutUint16(counter, count)

		streamCipher.XORKeyStream(aesRngBuf[aes.BlockSize:], counter)

		//So there is no predictable iv appended to the random src
		appendTmp := aesRngBuf[aes.BlockSize : aes.BlockSize+16]
		s.source = append(s.source, appendTmp...)
		count++
	}

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
