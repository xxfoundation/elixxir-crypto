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
	"crypto/cipher"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/csprng"
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
	AESCtr     cipher.Stream
	entropyCnt uint
	rng        csprng.Source
	src        []byte
	numStream  uint
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
func (sg *StreamGenerator) NewStream() *Stream {
	if sg.numStreams == sg.maxStreams {
		jww.FATAL.Printf("Attempting to create too many streams")
	}
	tmpStream := &Stream{
		streamGen:  sg,
		numStream:  sg.numStreams,
		entropyCnt: 20, //Some default value for our use?,

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
