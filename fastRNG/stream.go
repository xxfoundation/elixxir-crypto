////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// Package fastRNG is an implementation of the Fortuna construction as specified
// by Ferguson, Schneier and Kohno in 'Cryptography Engineering: Design Principles and Practical Applications'
// Link: https://www.schneier.com/academic/paperfiles/fortuna.pdf
package fastRNG

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	jww "github.com/spf13/jwalterweatherman"
	"git.xx.network/xx_network/crypto/csprng"
	_ "golang.org/x/crypto/blake2b"
	"hash"
	"sync"
)

type StreamGenerator struct {
	waitingStreams chan *stream
	scalingFactor  uint
	rngConstructor csprng.SourceConstructor
}

type Stream struct {
	*stream
	gen *StreamGenerator
}

type stream struct {
	//configuration
	scalingFactor uint

	//cryptographic primatives
	rng         csprng.Source
	AESCtr      cipher.Stream
	fortunaHash hash.Hash

	//state
	entropyCnt uint
	source     []byte

	//thread control
	mutex sync.Mutex
}

// NewStreamGenerator creates a StreamGenerator object containing
// streamCount streams. The passed in rngConstructor will be the source of
// randomness for the streams.
// maxWaiting allows the creation of a pool for the reuse of streams. To reuse a
// stream it must be closed, then it will be returned on the next attempted
// get of a new stream. Set it to zero if reuse isn't wanted
func NewStreamGenerator(scalingFactor uint, maxWaiting uint,
	rng csprng.SourceConstructor) *StreamGenerator {

	newStreamGenerator := StreamGenerator{
		scalingFactor:  scalingFactor,
		waitingStreams: make(chan *stream, maxWaiting),
		rngConstructor: rng,
	}

	return &newStreamGenerator
}

// newStream creates a new stream, having it point to the corresponding stream generator
// Also increment the amount of streams created in the stream generator
// Bookkeeping slice for streams made
func (sg *StreamGenerator) newStream() *stream {
	return &stream{
		scalingFactor: sg.scalingFactor,
		entropyCnt:    1,
		fortunaHash:   crypto.BLAKE2b_256.New(),
		rng:           sg.rngConstructor(),
	}
}

// GetStream gets an existing stream or creates a new stream object.
// It returns a new stream object if none can be retrieved from the pool of
// waiting streams
func (sg *StreamGenerator) GetStream() *Stream {
	var s *stream
	select {
	case s = <-sg.waitingStreams:
	default:
		s = sg.newStream()
	}
	return &Stream{
		stream: s,
		gen:    sg,
	}
}

// Close closes the stream object, locking it from external users and
// adding it back to the stream pool. The stream is dropped if the pool is full
func (sg *StreamGenerator) close(stream *stream) {
	select {
	case sg.waitingStreams <- stream:
	default:
		jww.WARN.Printf("Failed to recycle stream, " +
			"could not send to channel")
	}
}

// Read reads up to len(b) bytes from the csprng.Source object. This function returns and error if the stream is locked.
// Users of stream objects should close them when they are finished using them. We read the AES
// BlockSize into AES then run it until blockSize*scalingFactor bytes are read. Every time
// BlockSize*scalingFactor bytes are read this functions blocks until it rereads csprng.Source.
// Will crash if the stream has been closed.
func (s *stream) Read(b []byte) (int, error) {
	if s == nil {
		jww.FATAL.Panicf("Stream is closed, cannot read")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	numBlocks := len(b) / aes.BlockSize

	if len(b)%aes.BlockSize != 0 {
		numBlocks++
	}

	dst := s.source
	// A tmp buffer that has size a multiple of aes.BlockSize
	//TODO: This is due for a refactor, especially the tests.
	d := make([]byte, numBlocks*aes.BlockSize)

	//Initialize a counter to be used in Fortuna
	counter := make([]byte, aes.BlockSize)
	count := uint64(0)
	for block := 0; block < numBlocks; block++ {
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
			s.entropyCnt = s.scalingFactor
			s.AESCtr = Fortuna(dst, extension, s.fortunaHash)
		}

		dst = d[block*aes.BlockSize : (block+1)*aes.BlockSize]
		s.AESCtr.XORKeyStream(dst, counter)
	}

	copy(s.source, dst)
	copy(b, d[:len(b)])

	return len(b), nil
}

// Closes the stream returning it to its source generator if there is room in
// the pool
func (s *Stream) Close() {
	if s.stream == nil {
		jww.FATAL.Panicf("Stream is closed, cannot close")
	}

	st := s.stream

	s.stream = nil

	s.gen.close(st)
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
func (s *stream) SetSeed(seed []byte) error {
	jww.INFO.Printf("stream does not utilise SetSeed().")
	return nil
}
