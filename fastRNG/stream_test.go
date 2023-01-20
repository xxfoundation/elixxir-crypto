////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package fastRNG

import (
	"bytes"
	"crypto/rand"
	"gitlab.com/xx_network/crypto/csprng"
	"io"
	"testing"
)

// Line will error if the stream does not comply with the csprng.Source
// interface.
var _ csprng.Source = &stream{}

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
	if cap(sg.waitingStreams) != 20 || sg.scalingFactor != 12 {
		t.Errorf("Failure to initialize a stream generator correctly")
	}
}

//Test the creation of new streams and that the counters are in fact working
func TestNewStream(t *testing.T) {
	sg := NewStreamGenerator(12, 3, csprng.NewSystemRNG)
	s1 := sg.GetStream()
	if s1.entropyCnt != 1 {
		t.Errorf("New stream is not new")
	}
	s2 := sg.GetStream()
	if s2.entropyCnt != 1 {
		t.Errorf("New stream is not new")
	}
}

//Test that a blocked channel will grab a stream that is available
func TestGetStream_GrabsAlreadyWaitingStream(t *testing.T) {
	sg := NewStreamGenerator(43, 3, csprng.NewSystemRNG)
	stream0 := sg.GetStream()

	stream1 := sg.GetStream()
	sg.GetStream()
	//Allow the main thread to block as streams aren't available, then close it
	b := make([]byte, 32)
	stream0.Read(b)
	stream1.Read(b)
	stream0.Close()
	stream1.Close()

	s4 := sg.GetStream()
	if s4.entropyCnt != 42 {
		t.Errorf("New stream is not old: %d", s4.entropyCnt)
	}
}

func TestClose_WaitingChannelLength(t *testing.T) {
	sg := NewStreamGenerator(12, 3, csprng.NewSystemRNG)
	stream0 := sg.GetStream()
	stream1 := sg.GetStream()
	stream2 := sg.GetStream()

	//Close all the streams created
	stream0.Close()
	stream1.Close()
	stream2.Close()

	//Check that the waiting streams channel is the appropriate length
	if len(sg.waitingStreams) != 3 {
		t.Errorf("Waiting channel isn't the appropriate size after closing streams")
	}
}

// Tests that the read length is not byte aligned
func TestRead_ClosedChannel(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
		}
	}()

	sg := NewStreamGenerator(12, 3, csprng.NewSystemRNG)
	stream0 := sg.GetStream()
	requestedBytes := make([]byte, 95)
	testSource := make([]byte, 128, 128)
	stream0.source = testSource

	stream0.Close()

	_, _ = stream0.Read(requestedBytes)

	t.Errorf("Read didnt panc when it should")
}

// Tests that the read length is not byte aligned
func TestClose_ClosedChannel(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
		}
	}()

	sg := NewStreamGenerator(12, 3, csprng.NewSystemRNG)
	stream0 := sg.GetStream()

	stream0.Close()

	stream0.Close()

	t.Errorf("Close didnt panic when it should")
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

	if err != nil {
		t.Errorf("Error returned by Read() when not expected: %v", err)
	}
}

// Tests that the read length is byte aligned
func TestRead_ByteAligned(t *testing.T) {
	sg := NewStreamGenerator(12, 3, csprng.NewSystemRNG)
	stream0 := sg.GetStream()
	//96 is a multiple of 16 (AES Blocksize)
	requestedBytes := make([]byte, 96)
	testSource := make([]byte, 128, 128)
	stream0.source = testSource
	stream0.rng = csprng.NewSystemRNG()
	_, err := stream0.Read(requestedBytes)

	if err != nil {
		t.Errorf("Error returned by Read() nil when not expected. Read must be aligned by AES blocksize")
	}
}

// Checking that the fortuna construct outputs random when reading more than source has
func TestRead_ReadMoreThanSource(t *testing.T) {
	requestedBytes := make([]byte, 512)
	//Mock random source, of arbitrarily insufficient (small) size
	testSource := make([]byte, 256, 256)
	_, err := io.ReadFull(rand.Reader, testSource)
	if err != nil {
		t.Errorf("failed to read from io reader: %s", err)
	}

	//Initialize streamGenerator & streams
	sg := NewStreamGenerator(20, 2, csprng.NewSystemRNG)
	stream := sg.GetStream()
	stream.source = append(stream.source, testSource...)
	stream.rng = csprng.NewSystemRNG()

	//Initialize the stream with the generator
	_, err = stream.Read(requestedBytes)
	if err != nil {
		t.Fatal(err)
	}

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
		t.Errorf("failed to read from io reader: %s", err)
	}
	_, err1 := io.ReadFull(rand.Reader, testSource1)
	if err1 != nil {
		t.Errorf("failed to read from io reader: %s", err)
	}

	sg := NewStreamGenerator(20, 2, csprng.NewSystemRNG)
	stream0 := sg.GetStream()
	stream1 := sg.GetStream()

	stream0.source = testSource0
	stream1.source = testSource1
	stream0.rng = csprng.NewSystemRNG()
	stream1.rng = csprng.NewSystemRNG()

	_, err = stream0.Read(requestedBytes)
	if err != nil {
		// should never happen
		t.Fatal(err)
	}
	_, err = stream1.Read(requestedBytes)
	if err != nil {
		// should never happen
		t.Fatal(err)
	}

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
		t.Errorf("failed to read from io reader: %s", err)
	}

	//Initialize streamGenerator & streams
	sg := NewStreamGenerator(20, 2, csprng.NewSystemRNG)
	stream := sg.GetStream()
	stream.source = append(stream.source, testSource...)
	stream.rng = csprng.NewSystemRNG()
	//Initialize the stream with the generator
	_, err = stream.Read(requestedBytes)
	if err != nil {
		// should never happen
		t.Fatal(err)
	}
	sourceAfterRead := make([]byte, len(stream.source))
	copy(sourceAfterRead, stream.source)
	//Overwrite the entirety of requestedBytes
	_, err2 := io.ReadFull(rand.Reader, requestedBytes)
	if err2 != nil {
		t.Errorf("failed to read from io reader: %s", err)
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
	_, err = stream.Read(requestedBytes)
	if err != nil {
		// should never happen
		t.Fatal(err)
	}
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
