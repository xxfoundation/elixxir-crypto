////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package backup

import (
	"bytes"
	"encoding/binary"
	"github.com/pkg/errors"
)

// Length of fields in the Params object.
const (
	paramTimeLen    = 4
	paramMemoryLen  = 4
	paramThreadsLen = 1

	// ParamsLen is the length of the marshalled Params object.
	ParamsLen = paramTimeLen + paramMemoryLen + paramThreadsLen
)

// Error messages.
const (
	// Params.Unmarshal
	errReadTime    = "read Time param failed: %+v"
	errReadMemory  = "read Memory param failed: %+v"
	errReadThreads = "read Threads param failed: %+v"
)

// Params contains the cost parameters used by Argon2.
type Params struct {
	Time    uint32 `json:"time"`    // Number of passes over the memory
	Memory  uint32 `json:"memory"`  // Amount of memory used in KiB
	Threads uint8  `json:"threads"` // Number of threads used
}

// DefaultParams returns the recommended general purposes parameters.
func DefaultParams() Params {
	return Params{
		Time:    1,
		Memory:  64 * 1024, // ~64 MB
		Threads: 4,
	}
}

// testParams returns params used in testing that are quick.
func testParams() Params {
	return Params{
		Time:    1,
		Memory:  1,
		Threads: 1,
	}
}

// Marshal marshals the Params object into a byte slice.
func (p *Params) Marshal() []byte {
	buff := bytes.NewBuffer(nil)
	buff.Grow(ParamsLen)

	// Write Time to buffer
	b := make([]byte, paramTimeLen)
	binary.LittleEndian.PutUint32(b, p.Time)
	buff.Write(b)

	// Write Memory to buffer
	b = make([]byte, paramMemoryLen)
	binary.LittleEndian.PutUint32(b, p.Memory)
	buff.Write(b)

	// Write Threads to buffer
	buff.WriteByte(p.Threads)

	return buff.Bytes()
}

// Unmarshal decodes the byte slice into a Params objects.
func (p *Params) Unmarshal(buf []byte) error {
	buff := bytes.NewBuffer(buf)

	err := binary.Read(buff, binary.LittleEndian, &p.Time)
	if err != nil {
		return errors.Errorf(errReadTime, err)
	}

	err = binary.Read(buff, binary.LittleEndian, &p.Memory)
	if err != nil {
		return errors.Errorf(errReadMemory, err)
	}

	err = binary.Read(buff, binary.LittleEndian, &p.Threads)
	if err != nil {
		return errors.Errorf(errReadThreads, err)
	}

	return nil
}
