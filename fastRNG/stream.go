////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

// Package fastRNG is an implementation of the Fortuna construction as specified
// by Ferguson, Schneier and Kohno in 'Cryptography Engineering: Design Principles and Practical Applications'
// Link: https://www.schneier.com/academic/paperfiles/fortuna.pdf
package fastRNG

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/csprng"
	_ "golang.org/x/crypto/blake2b"
	"hash"
	"sync"
)

type StreamGenerator struct {
	streams        []*Stream
	waitingStreams chan *Stream
	maxStreams     uint
	numStreams     uint
	scalingFactor  uint
	rngConstructor csprng.SourceConstructor
}

type Stream struct {
	streamGen   *StreamGenerator
	AESCtr      cipher.Stream
	entropyCnt  uint
	rng         csprng.Source
	source      []byte
	numStream   uint
	mutex       sync.Mutex
	fortunaHash hash.Hash
}

// NewStreamGenerator creates a StreamGenerator object containing up to
// streamCount streams. The passed in rngConstructor will be the source of
// randomness for the streams.
func NewStreamGenerator(scalingFactor uint, streamCount uint,
	rng csprng.SourceConstructor) *StreamGenerator {
	return &StreamGenerator{
		scalingFactor:  scalingFactor,
		waitingStreams: make(chan *Stream, streamCount),
		maxStreams:     streamCount,
		numStreams:     uint(0),
		streams:        make([]*Stream, 0, streamCount),
		rngConstructor: rng,
	}
}

// newStream creates a new stream, having it point to the corresponding stream generator
// Also increment the amount of streams created in the stream generator
// Bookkeeping slice for streams made
func (sg *StreamGenerator) newStream() *Stream {
	if sg.numStreams == sg.maxStreams {
		jww.FATAL.Panicf("Attempting to create too many streams")
		return &Stream{}
	}
	tmpStream := &Stream{
		streamGen:   sg,
		numStream:   sg.numStreams,
		entropyCnt:  1,
		fortunaHash: crypto.BLAKE2b_256.New(),
		rng:         sg.rngConstructor(),
	}
	sg.streams = append(sg.streams, tmpStream)
	sg.numStreams++
	return tmpStream
}

// GetStream gets an existing stream or creates a new Stream object.
// If the # of open streams exceeds streamCount,
// this function blocks (and prints a log warning) until a stream is available
func (sg *StreamGenerator) GetStream() *Stream {
	var retStream *Stream

	// If there is a stream waiting to be used, take that from the channel and return in
	select {
	case retStream = <-sg.waitingStreams:
	default:
	}

	// If there was no waiting channels, ie we exited the select statement
	if retStream == nil {
		// If we have not reached the maximum amount of streams (specified by streamCount), then create a new one
		if sg.numStreams < sg.maxStreams {
			retStream = sg.newStream()
		} else {
			// Else block until a stream is put in the waiting channel
			retStream = <-sg.waitingStreams
		}
	}
	return retStream
}

// Close closes the stream object, locking it from external users and marking it as available in the stream list
func (sg *StreamGenerator) Close(stream *Stream) {
	sg.waitingStreams <- stream
}

// Read reads up to len(b) bytes from the csprng.Source object. This function returns and error if the stream is locked.
// Users of stream objects should close them when they are finished using them. We read the AES
// BlockSize into AES then run it until blockSize*scalingFactor bytes are read. Every time
// BlockSize*scalingFactor bytes are read this functions blocks until it rereads csprng.Source.
func (s *Stream) Read(b []byte) (int, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if len(b)%aes.BlockSize != 0 {
		return 0, errors.New("requested read length is not byte aligned")
	}

	dst := s.source

	//Initialize a counter to be used in Fortuna
	counter := make([]byte, aes.BlockSize)
	count := uint64(0)
	for block := 0; block < len(b)/aes.BlockSize; block++ {
		// Little endian used as a straightforward way to increment a byte array
		count++
		binary.LittleEndian.PutUint64(counter, count)
		var extension []byte
		// Decrease the entropy count
		s.entropyCnt--

		// If entropyCnt is decreased too far, add an extension and set the entropyCnt
		if s.entropyCnt == 0 {
			extension = make([]byte, aes.BlockSize)
			_, err := s.rng.Read(extension)
			if err != nil {
				return 0, err
			}
			s.entropyCnt = s.streamGen.scalingFactor
			s.AESCtr = Fortuna(dst, extension, s.fortunaHash)
		}

		dst = b[block*aes.BlockSize : (block+1)*aes.BlockSize]
		s.AESCtr.XORKeyStream(dst, counter)
	}

	copy(s.source, dst)

	return len(b), nil
}

// The Fortuna construction is used to generate randomness
func Fortuna(src, ext []byte, fortunaHash hash.Hash) cipher.Stream {
	// Create a key based on the hash of the src and an extension
	// extension used if entropyCnt had reached 0
	fortunaHash.Reset()
	fortunaHash.Write(src)
	fortunaHash.Write(ext)
	key := fortunaHash.Sum(nil)

	// Initialize a block cipher on that key
	block, err := aes.NewCipher(key[:aes.BlockSize])
	if err != nil {
		jww.FATAL.Panicf(err.Error())
	}

	// Encrypt the counter and place into destination
	return cipher.NewCTR(block, key[aes.BlockSize:2*aes.BlockSize])
}

// SetSeed does not do anything. Function exists to comply with the
// csprng.Source interface.
func (s *Stream) SetSeed(seed []byte) error {
	jww.INFO.Printf("Stream does not utilise SetSeed().")
	return nil
}
