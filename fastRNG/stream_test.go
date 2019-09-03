///////////////////////////////////////////////////////////////////////////////
// Copyright © 2019 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////
package fastRNG

import (
	"bytes"
	"crypto/rand"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/csprng"
	"io"
	"reflect"
	"testing"
	"time"
)

// Line will error if the stream does not comply with the csprng.Source
// interface.
var _ csprng.Source = &Stream{}

// Mock struct and members for a mockRead test
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
	sg := NewStreamGenerator(12, 20, csprng.NewSystemRNG)
	if sg.maxStreams != 20 || sg.scalingFactor != 12 {
		t.Errorf("Failure to initialize a stream generator correctly")
	}
}

//Test the creation of new streams and that the counters are in fact working
func TestNewStream(t *testing.T) {
	sg := NewStreamGenerator(12, 3, csprng.NewSystemRNG)
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
	sg := NewStreamGenerator(12, 2, csprng.NewSystemRNG)
	sg.newStream()
	sg.newStream()
	sg.newStream()
	//It should panic after the 3rd newStream and get deferred. If it doesn't it has failed
	t.Errorf("FastRNG should panic when too many streams are made!")

}

//Test that it does not panic when it reaches capacity
func TestNewStream_NotPanic(t *testing.T) {
	//The defer function should not be encountered here, as we are not exceeding capacity, we are at it
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("FastRNG should not panic when there are exactly maxStream Streams")
		}
	}()
	//Stream count is 2, and 2 streams are being created, thus it should not panic
	sg := NewStreamGenerator(12, 2, csprng.NewSystemRNG)
	sg.newStream()
	sg.newStream()
}

//Test that the getStream calls newStream correctly/appropriately
func TestGetStream_NewStream(t *testing.T) {
	sg := NewStreamGenerator(12, 3, csprng.NewSystemRNG)
	sg.GetStream()
	sg.GetStream()
	sg.GetStream()

	if sg.numStreams != uint(len(sg.streams)) && sg.numStreams != 3 {
		t.Errorf("New streams bookkeeping is not working.")
	}
}

//Test that a blocked channel will grab a stream what it becomes available
func TestGetStream_GrabsWaitingStream(t *testing.T) {
	sg := NewStreamGenerator(12, 3, csprng.NewSystemRNG)
	stream0 := sg.GetStream()
	sg.GetStream()
	sg.GetStream()
	//Allow the main thread to block as streams aren't available, then close it
	go func() {
		time.Sleep(1 * time.Second)
		sg.Close(stream0)
	}()
	newStream := sg.GetStream()
	if !reflect.DeepEqual(newStream, stream0) {
		t.Errorf("The next stream did not grab the correct stream")
	}
}

//Test that a blocked channel will grab a stream that is available
func TestGetStream_GrabsAlreadyWaitingStream(t *testing.T) {
	sg := NewStreamGenerator(12, 3, csprng.NewSystemRNG)
	stream0 := sg.GetStream()

	steam1 := sg.GetStream()
	sg.GetStream()
	//Allow the main thread to block as streams aren't available, then close it
	sg.Close(stream0)
	sg.Close(steam1)

	newStream := sg.GetStream()
	if !reflect.DeepEqual(newStream, sg.streams[0]) {
		t.Errorf("The next stream did not grab the correct stream")
	}
}

func TestClose_WaitingChannelLength(t *testing.T) {
	sg := NewStreamGenerator(12, 3, csprng.NewSystemRNG)
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

// Tests that the read length is not byte aligned
func TestRead_NotByteAligned(t *testing.T) {
	sg := NewStreamGenerator(12, 3, csprng.NewSystemRNG)
	stream0 := sg.GetStream()
	requestedBytes := make([]byte, 95)
	testSource := make([]byte, 128, 128)
	stream0.source = testSource
	stream0.rng = csprng.NewSystemRNG()
	_, err := stream0.Read(requestedBytes)

	if err == nil {
		t.Errorf("Error returned by Read() nil when not expected.")
	}
}

// Checking that the fortuna construct outputs random when reading more than source has
func TestRead_ReadMoreThanSource(t *testing.T) {
	requestedBytes := make([]byte, 512)
	//Mock random source, of arbitrarily insufficient (small) size
	testSource := make([]byte, 256, 256)
	_, err := io.ReadFull(rand.Reader, testSource)
	if err != nil {
		jww.WARN.Printf(err.Error())
	}

	//Initialize streamGenerator & streams
	sg := NewStreamGenerator(20, 2, csprng.NewSystemRNG)
	stream := sg.GetStream()
	stream.source = append(stream.source, testSource...)
	stream.rng = csprng.NewSystemRNG()

	//Initialize the stream with the generator
	stream.Read(requestedBytes)

	//Make sure that the original source and the original entropyCnt are not same after read
	if bytes.Compare(stream.source, testSource) == 0 {
		t.Errorf("Fortuna construction did not add randomness to the source")
	}
}

//Test that different streams under same stream generator output differently upon reading
func TestRead_MultipleStreams_DifferentOutputs(t *testing.T) {
	//A large byte array, of which you will read size from src byte array
	requestedBytes := make([]byte, 512)
	testSource0 := make([]byte, 256, 256)
	testSource1 := make([]byte, 256, 256)
	_, err := io.ReadFull(rand.Reader, testSource0)
	if err != nil {
		jww.WARN.Printf(err.Error())
	}
	_, err1 := io.ReadFull(rand.Reader, testSource1)
	if err1 != nil {
		jww.WARN.Printf(err.Error())
	}

	sg := NewStreamGenerator(20, 2, csprng.NewSystemRNG)
	stream0 := sg.GetStream()
	stream1 := sg.GetStream()

	stream0.source = testSource0
	stream1.source = testSource1
	stream0.rng = csprng.NewSystemRNG()
	stream1.rng = csprng.NewSystemRNG()

	stream0.Read(requestedBytes)
	stream1.Read(requestedBytes)

	if bytes.Compare(stream0.source, stream1.source) == 0 {
		t.Errorf("Streams should not produce the same output with different sources upon reading")
	}
}

//Test that b (requestedBytes) is delinked from source by overwriting b and checking that source has not changed
func TestRead_DelinkedSource(t *testing.T) {
	//A large byte array, of which you will read size from src byte array
	requestedBytes := make([]byte, 512)
	//Mock random source, of arbitrarily insufficient (small) size
	testSource := make([]byte, 256, 256)
	_, err := io.ReadFull(rand.Reader, testSource)
	if err != nil {
		jww.WARN.Printf(err.Error())
	}

	//Initialize streamGenerator & streams
	sg := NewStreamGenerator(20, 2, csprng.NewSystemRNG)
	stream := sg.GetStream()
	stream.source = append(stream.source, testSource...)
	stream.rng = csprng.NewSystemRNG()
	//Initialize the stream with the generator
	stream.Read(requestedBytes)
	sourceAfterRead := make([]byte, len(stream.source))
	copy(sourceAfterRead, stream.source)
	//Overwrite the entirety of requestedBytes
	_, err2 := io.ReadFull(rand.Reader, requestedBytes)
	if err2 != nil {
		jww.WARN.Printf(err2.Error())
	}
	//Test if source has changed from it's copy
	if bytes.Compare(sourceAfterRead, stream.source) != 0 {
		t.Errorf("The reading byte slice and the stream's source have not been delinked")
	}
}

// Read read a length smaller than the currently existing source
func TestRead_ReadLessThanSource(t *testing.T) {
	sg := NewStreamGenerator(20, 2, csprng.NewSystemRNG)
	stream := sg.GetStream()
	requestedBytes := make([]byte, 32)
	origSrcLen := 234
	testSource := make([]byte, origSrcLen, origSrcLen)

	//Initialize everything needed in stream for a read
	_, err := io.ReadFull(rand.Reader, testSource)
	if err != nil {
		panic(err.Error())
	}
	stream.source = testSource
	stream.rng = csprng.NewSystemRNG()
	stream.Read(requestedBytes)
	if len(stream.source) != origSrcLen {
		t.Errorf("Unexpected lengthening of the stream's source")
	}
}

//Test with a mock read that returns predictably every time
func TestRead_MockRNG(t *testing.T) {
	sg := NewStreamGenerator(20, 2, csprng.NewSystemRNG)
	read := make([]byte, 24)
	stream := sg.GetStream()
	stream.rng = newMockRNG()
	length, err := stream.rng.Read(read)
	if length != 0 || err != nil {
		t.Errorf("Mock read failed")
	}
}

func TestStream_SetSeed(t *testing.T) {
	sg := NewStreamGenerator(20, 2, csprng.NewSystemRNG)
	stream := sg.GetStream()

	err := stream.SetSeed([]byte{})

	if err != nil {
		t.Errorf("Error returned by SetSeed() not nil when expected.")
	}
}
