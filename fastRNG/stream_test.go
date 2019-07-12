///////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////
package fastRNG

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"gitlab.com/elixxir/crypto/csprng"
	"io"
	"reflect"
	"testing"
	"time"
)

type mockRNG struct {
}

func newMockRNG() csprng.Source {
	return &mockRNG{}
}
func (m *mockRNG) Read(b []byte) (int, error) {
	return 0, nil
}
func (m *mockRNG) SetSeed(seed []byte) error {
	return nil
}

//Test the creation of a new stream generator and that it is configured correctly
func TestNewStreamGenerator(t *testing.T) {
	sg := NewStreamGenerator(12, 20)
	if sg.maxStreams != 20 || sg.scalingFactor != 12 {
		t.Errorf("Failure to initialize a stream generator correctly")
	}
}

//Test the creation of new streams and that the counters are in fact working
func TestNewStream(t *testing.T) {
	sg := NewStreamGenerator(12, 3)
	sg.GetStream()
	sg.GetStream()
	sg.GetStream()
	//See if there are the appropriate amount of streams in the streams slice and the stream count
	if sg.numStreams != uint(len(sg.streams)) && sg.numStreams != 3 {
		t.Errorf("New streams bookkeeping is not working.")
	}
}

//Test that the stream generator panics when there are too many streams being made
func TestNewStream_DoesPanic(t *testing.T) {
	//The defer function will catch the panic
	defer func() {
		if r := recover(); r != nil {

		}
	}()
	//Stream count is 2, but 3 streams are being created, thus it should panic
	sg := NewStreamGenerator(12, 2)
	sg.newStream()
	sg.newStream()
	sg.newStream()
	//It should panic after the 3rd newStream and get deffered. If it doesn't it has failed
	t.Errorf("FastRNG should panic when too many streams are made!")

}

//Test that it does not panic when it reaches capacity
func TestNewStream_NotPanic(t *testing.T) {
	//The defer function should not be encountered here, as we are not exceeding capactity, we are at it
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("FastRNG should not panic when there are exactly maxStream Streams")
		}
	}()
	//Stream count is 2, and 2 streams are being created, thus it should not panic
	sg := NewStreamGenerator(12, 2)
	sg.newStream()
	sg.newStream()
}

//Test that the getStream calls newStream correctly/appropriately
func TestGetStream_NewStream(t *testing.T) {
	sg := NewStreamGenerator(12, 3)
	sg.GetStream()
	sg.GetStream()
	sg.GetStream()

	if sg.numStreams != uint(len(sg.streams)) && sg.numStreams != 3 {
		t.Errorf("New streams bookkeeping is not working.")
	}
}

//Test that a blocked channel will grab a stream when it becomes available
func TestGetStream_GrabsWaitingStream(t *testing.T) {
	sg := NewStreamGenerator(12, 3)
	stream0 := sg.GetStream()
	sg.GetStream()
	sg.GetStream()
	//Allow the main thread to block as streams aren't available, then close it
	go func() {
		time.Sleep(500 * time.Millisecond)
		sg.Close(stream0)
	}()
	newStream := sg.GetStream()
	if !reflect.DeepEqual(newStream, stream0) {
		t.Errorf("The next stream did not grab the correct stream")
	}
}

func TestClose_WaitingChannelLength(t *testing.T) {
	sg := NewStreamGenerator(12, 3)
	stream0 := sg.GetStream()
	stream1 := sg.GetStream()
	stream2 := sg.GetStream()

	//Close all the streams created
	sg.Close(stream0)
	sg.Close(stream1)
	sg.Close(stream2)

	//Check that the waiting streams channel is the appropriate length
	if len(sg.waitingStreams) != 3 {
		t.Errorf("Waiting channel isn't the appropriate size after closing streams")
	}
}

func TestFortunaConstruction(t *testing.T) {
	sg := NewStreamGenerator(12, 3)
	stream0 := sg.GetStream()
	requestedBytes := make([]byte, 96)
	testSource := make([]byte, 128, 128)
	_, err := io.ReadFull(rand.Reader, testSource)
	if err != nil {
		panic(err.Error())
	}
	stream0.source = testSource
	//stream0.AESCtr = ciph
	stream0.rng = csprng.NewSystemRNG()
	fmt.Println(stream0.source)
	stream0.Read(requestedBytes)
	fmt.Println(stream0.source)

}

// Tests that the read length is byte aligned
// Tests that the read length is byte aligned
func TestRead_NotByteAligned(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {

		}
	}()
	sg := NewStreamGenerator(12, 3)
	stream0 := sg.GetStream()
	requestedBytes := make([]byte, 95)
	testSource := make([]byte, 128, 128)
	stream0.source = testSource
	stream0.rng = csprng.NewSystemRNG()
	stream0.Read(requestedBytes)
	t.Errorf("Test should have panicked here, read must be aligned by AES blocksize")
}

func TestRead_ByteAligned(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Test should not have panicked here, read must be aligned by AES blocksize")
		}
	}()
	sg := NewStreamGenerator(12, 3)
	stream0 := sg.GetStream()
	//96 is a multiple of 16 (AES Blocksize)
	requestedBytes := make([]byte, 96)
	testSource := make([]byte, 128, 128)
	stream0.source = testSource
	stream0.rng = csprng.NewSystemRNG()
	stream0.Read(requestedBytes)
}

// Checking the functionality of appending the source using the Fortuna construction
func TestRead_ReadMoreThanSource(t *testing.T) {

	//A large byte array, of which you will read size from src byte array
	requestedBytes := make([]byte, 128)

	/*Initialize everything needed for stream*/

	//Mock random source, of arbitrarily insufficient (small) size
	testSource := make([]byte, 16, 16)
	_, err := io.ReadFull(rand.Reader, testSource)
	if err != nil {
		panic(err.Error())
	}

	//Initialize streamGenerator & streams
	sg := NewStreamGenerator(20, 2)
	stream := sg.GetStream()
	stream.source = testSource
	stream.rng = csprng.NewSystemRNG()
	//Initialize the stream with the generator
	fmt.Println("orig source")
	fmt.Println(testSource)
	stream.Read(requestedBytes)
	fmt.Println("after read")
	fmt.Println(stream.source)
	//Make sure that the original source and the original entropyCnt are not same after read
	if bytes.Compare(stream.source, testSource) == 0 {
		t.Errorf("Fortuna construction did not add randomness to the source")
	}
}

// Read read a length smaller than the currently existing source
//In this case, extend source should not be called, thus the len of src should not change
func TestRead_ReadLessThanSource(t *testing.T) {
	sg := NewStreamGenerator(20, 2)
	stream := sg.GetStream()
	requestedBytes := make([]byte, 32)
	origSrcLen := 2048
	testSource := make([]byte, origSrcLen, origSrcLen)

	//Initialize everything needed in stream for a read
	_, err := io.ReadFull(rand.Reader, testSource)
	if err != nil {
		panic(err.Error())
	}
	//Mock block cipher

	stream.source = testSource
	stream.rng = csprng.NewSystemRNG()

	stream.Read(requestedBytes)
	if len(stream.source) != origSrcLen || stream.entropyCnt == 0 {
		t.Errorf("Unexpected lengthening of the stream's source")
	}
}

//Test with a mock read that returns predictably every time
func TestRead_MockRNG(t *testing.T) {
	sg := NewStreamGenerator(20, 2)
	read := make([]byte, 24)
	stream := sg.GetStream()
	stream.rng = newMockRNG()
	length, err := stream.rng.Read(read)
	if length != 0 || err != nil {
		t.Errorf("Mock read failed")
	}
}
