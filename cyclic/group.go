////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// Package cyclic wraps our large.Int structure.  It is designed to be used in
// conjunction with the cyclic.Group object. The cyclic.Group object
// will provide implementations of various modular operations within the group.
// A cyclic.IntBuffer type will be created to store large batches of groups.
package cyclic

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/gob"
	"encoding/json"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/large"
)

// Groups provide cyclic int operations that keep the return values confined to
// a finite field under modulo p
type Group struct {
	psub1       *large.Int
	psub2       *large.Int
	psub3       *large.Int
	prime       *large.Int
	psub1factor *large.Int
	zero        *large.Int
	one         *large.Int
	two         *large.Int
	gen         *large.Int
	rng         csprng.Source
	random      []byte
	fingerprint uint64
	primeBytes  []byte
}

const GroupFingerprintSize = 8

// NewGroup returns a group with the given prime and generator
func NewGroup(p, g *large.Int) *Group {
	h := sha256.New()
	h.Write(p.Bytes())
	h.Write(g.Bytes())
	hashVal := h.Sum(nil)[:GroupFingerprintSize]
	value := large.NewIntFromBytes(hashVal)
	return &Group{
		prime:       p,
		psub1:       large.NewInt(1).Sub(p, large.NewInt(1)),
		psub2:       large.NewInt(1).Sub(p, large.NewInt(2)),
		psub3:       large.NewInt(1).Sub(p, large.NewInt(3)),
		psub1factor: large.NewInt(1).RightShift(large.NewInt(1).Sub(p, large.NewInt(1)), 1),

		zero:        large.NewInt(0),
		one:         large.NewInt(1),
		two:         large.NewInt(2),
		gen:         g,
		rng:         csprng.NewSystemRNG(),
		random:      make([]byte, (p.BitLen()+7)/8),
		fingerprint: value.Uint64(),
		primeBytes:  p.Bytes(),
	}
}

// -------------- Constructors -------------- //

// NewIntBuffer is a constructor for IntBuffer
// if defaultValue is nil, it is set to the max value possible in the group, p-1
func (g *Group) NewIntBuffer(length uint32, defaultValue *Int) *IntBuffer {
	var defaultValueLarge *large.Int

	if defaultValue == nil {
		defaultValueLarge = g.psub1.DeepCopy()
	} else {
		g.checkInts(defaultValue)
		defaultValueLarge = defaultValue.value.DeepCopy()
	}

	newBuffer := IntBuffer{make([]large.Int, length), g.fingerprint}
	for i := range newBuffer.values {
		(&newBuffer.values[i]).Set(defaultValueLarge)
	}
	return &newBuffer
}

// NewInt creates a new cyclicInt in the group from an int64 value
func (g *Group) NewInt(x int64) *Int {
	val := large.NewInt(x)
	n := &Int{value: val, fingerprint: g.fingerprint}
	if !g.Inside(n.value) {
		panic("NewInt: Attempted creation of cyclic outside of group")
	}
	return n
}

// NewIntFromLargeInt creates a new cyclicInt in the group from a large.Int value
func (g *Group) NewIntFromLargeInt(x *large.Int) *Int {
	n := &Int{value: x, fingerprint: g.fingerprint}
	if !g.Inside(n.value) {
		panic("NewIntFromLargeInt: Attempted creation of cyclic outside of group")
	}
	return n
}

// NewIntFromBytes creates a new cyclicInt in the group from a byte buffer
func (g *Group) NewIntFromBytes(buf []byte) *Int {
	val := large.NewIntFromBytes(buf)
	n := &Int{value: val, fingerprint: g.fingerprint}
	if !g.Inside(n.value) {
		panic("NewIntFromBytes: Attempted creation of cyclic outside of group")
	}
	return n
}

// NewIntFromString creates a new cyclicInt in the group from a string using the passed base
// returns nil if string cannot be parsed
func (g *Group) NewIntFromString(str string, base int) *Int {
	val := large.NewIntFromString(str, base)
	if val == nil {
		return nil
	}
	n := &Int{value: val, fingerprint: g.fingerprint}
	if !g.Inside(n.value) {
		panic("NewIntFromString: Attempted creation of cyclic outside of group")
	}
	return n
}

// NewMaxInt creates a new cyclicInt in the group at the max group value
func (g *Group) NewMaxInt() *Int {
	n := &Int{value: g.psub1, fingerprint: g.fingerprint}
	return n.DeepCopy()
}

// NewIntFromUInt creates a new cyclicInt in the group from an uint64 value
func (g *Group) NewIntFromUInt(i uint64) *Int {
	val := large.NewIntFromUInt(i)
	n := &Int{value: val, fingerprint: g.fingerprint}
	if !g.Inside(n.value) {
		panic("NewIntFromUInt: Attempted creation of cyclic outside of group")
	}
	return n
}

// NewIntFromBits creates a new cyclic int from a words array
// This method doesn't copy the bits array, so if you need a copy, copy the array before passing it in
func (g *Group) NewIntFromBits(b large.Bits) *Int {
	val := large.NewIntFromBits(b)
	n := &Int{
		value:       val,
		fingerprint: g.fingerprint,
	}
	if !g.Inside(n.value) {
		panic("NewIntFromBits: Attempted creation of cyclic outside of group")
	}
	return n
}

// Check if all cyclic Ints belong to the group and panic otherwise
func (g *Group) checkInts(ints ...*Int) {
	for _, i := range ints {
		if i.GetGroupFingerprint() != g.fingerprint {
			// The error is created separately to ensure that the stack trace is
			// printed on panic
			err := errors.Errorf("cyclicInt being used in wrong group! "+
				"Group fingerprint is %d and cyclicInt has %d",
				g.fingerprint, i.GetGroupFingerprint())
			jww.FATAL.Panicf("%+v", err)
		}
	}
}

// GetFingerprint gets the group's fingerprint
func (g *Group) GetFingerprint() uint64 {
	return g.fingerprint
}

func (g *Group) GetFingerprintText() string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, g.fingerprint)
	fullText := base64.StdEncoding.EncodeToString(buf)
	return fullText[:8] + "..."
}

// -------------- Setters -------------- //

// Set sets x to y in the group and returns x
func (g *Group) Set(x, y *Int) *Int {
	g.checkInts(x, y)
	x.value.Set(y.value)
	return x
}

// SetLargeInt sets x's value to y s.t. y is inside the group
func (g *Group) SetLargeInt(x *Int, y *large.Int) *Int {
	success := g.Inside(y)

	if !success {
		return nil
	}

	x.value.Set(y)

	return x
}

// SetBits sets x in the group to bits and returns x
// This method does not copy. If you need to set the number to a copy, please copy the bits outside of this.
func (g *Group) SetBits(x *Int, b large.Bits) *Int {
	x.value.SetBits(b)
	g.checkInts(x)
	return x
}

// OverwriteBits copies b over x. If there isn't enough memory
// available in x already, it allocates a new slice with enough memory
// Under no circumstance will b be the backing memory of the returned Int
// This is important for our usage of CGBN, which constantly overwrites the output memory
func (g *Group) OverwriteBits(x *Int, b large.Bits) *Int {
	bits := x.Bits()
	if cap(bits) >= len(b) {
		// Existing int is big enough; copying over existing bits is OK
		bits = bits[:cap(bits)]
		copy(bits, b)
		x.value.SetBits(bits[:len(b)])
	} else {
		// A new slice is needed, since the existing int isn't big enough
		newBits := make(large.Bits, len(b))
		copy(newBits, b)
		x.value.SetBits(newBits)
	}
	g.checkInts(x)
	return x
}

// SetBytes sets x in the group to bytes and returns x
func (g *Group) SetBytes(x *Int, buf []byte) *Int {
	x.value.SetBytes(buf)
	g.checkInts(x)
	return x
}

// SetString sets x in the group to string and returns x
// or nil if error parsing the string
func (g *Group) SetString(x *Int, s string, base int) *Int {
	g.checkInts(x)
	_, ret := x.value.SetString(s, base)
	if ret == false {
		return nil
	}
	return x
}

// SetMaxInt sets x in the group to Max4KInt value and returns x
func (g *Group) SetMaxInt(x *Int) *Int {
	g.checkInts(x)
	x.value.Set(g.psub1)
	return x
}

// SetUint64 sets x in the group to uint64 value and returns x
func (g *Group) SetUint64(x *Int, u uint64) *Int {
	g.checkInts(x)
	x.value.SetUint64(u)
	return x
}

// Mul multiplies a and b within the group, putting the result in c
// and returning c
func (g *Group) Mul(a, b, c *Int) *Int {
	g.checkInts(a, b, c)
	c.value.Mod(c.value.Mul(a.value, b.value), g.prime)
	return c
}

// Inside returns true of the Int is within the group, false if it isn't
func (g *Group) Inside(a *large.Int) bool {
	return a.Cmp(g.zero) == 1 && a.Cmp(g.prime) == -1
}

// bytesInside returns true of the all the Ints represented by the byte slices
// are within the group, false if it isn't
func (g *Group) BytesInside(buffers ...[]byte) bool {
	inside := true

	for _, buf := range buffers {
		inside = inside && g.singleBytesInside(buf)
	}

	return inside
}

// BytesInside returns true of the Int represented by the byte slice is within the group, false if it isn't
func (g *Group) singleBytesInside(buf []byte) bool {
	return csprng.InGroup(buf, g.primeBytes)
}

// ModP sets z ≡ x mod prime within the group and returns z.
func (g Group) ModP(x *large.Int, z *Int) *Int {
	g.checkInts(z)
	z.value.Mod(x, g.prime)
	return z
}

// Inverse sets b equal to the inverse of a within the group and returns b
func (g *Group) Inverse(a, b *Int) *Int {
	g.checkInts(a, b)
	b.value.ModInverse(a.value, g.prime)
	return b
}

// Random securely generates a random number in the group: 2 <= rand <= p-1
// Sets r to the number and returns it
func (g *Group) Random(r *Int) *Int {
	g.checkInts(r)
	rng := g.rng
	r.value.Set(g.one)
	for g.one.Cmp(r.value) == 0 {
		b, err := csprng.GenerateInGroup(g.primeBytes,
			len(g.primeBytes), rng)
		if err != nil {
			jww.FATAL.Panicf("Could not generate random number in group: %s", err)
		}
		r.value.SetBytes(b)
	}
	return r
}

// GetP returns a copy of the group's prime
func (g *Group) GetP() *large.Int {
	n := large.NewInt(1)
	n.Set(g.prime)
	return n
}

// GetG returns a copy of the group's generator
func (g *Group) GetG() *large.Int {
	n := large.NewInt(1)
	n.Set(g.gen)
	return n
}

// GetGCyclic returns a new cyclicInt with the group's generator
func (g *Group) GetGCyclic() *Int {
	return g.NewIntFromLargeInt(g.gen)
}

// GetPBytes returns a copy of the group's prime bytes
func (g *Group) GetPBytes() []byte {
	pCopy := make([]byte, len(g.primeBytes))
	copy(pCopy, g.primeBytes)
	return pCopy
}

// GetPSub1 returns a copy of the group's p-1
func (g *Group) GetPSub1() *Int {
	n := large.NewInt(1)
	n.Set(g.psub1)
	return &Int{n, g.fingerprint}
}

// GetPSub1Cyclic returns a new cyclicInt with the group's p-1
func (g *Group) GetPSub1Cyclic() *Int {
	return g.NewIntFromLargeInt(g.psub1)
}

// GetPSub1Factor returns a copy of the group's (p-1)/2
func (g *Group) GetPSub1Factor() *large.Int {
	n := large.NewInt(1)
	n.Set(g.psub1factor)
	return n
}

// GetPSub1FactorCyclic returns a new cyclicInt with the group's (p-1)/2
func (g *Group) GetPSub1FactorCyclic() *Int {
	return g.NewIntFromLargeInt(g.psub1factor)
}

// FullBytes gets cyclicInt left-padded to the size of the prime
func (g *Group) FullBytes(x *Int) []byte {
	return x.value.LeftpadBytes(uint64(g.prime.BitLen() >> 3))
}

// GroupMul Multiplies all ints in the passed slice slc together and
// places the result in c
func (g Group) MulMulti(c *Int, ints ...*Int) *Int {

	g.checkInts(append(ints, c)...)
	c.value.SetInt64(1)

	for _, islc := range ints {
		g.Mul(c, islc, c)
	}

	return c
}

// Exp sets z = x**y mod p, and returns z.
func (g Group) Exp(x, y, z *Int) *Int {
	g.checkInts(x, y, z)
	z.value.Exp(x.value, y.value, g.prime)
	return z
}

// ExpG sets z = g**y mod p, and returns z.
func (g Group) ExpG(y, z *Int) *Int {
	g.checkInts(y, z)
	z.value.Exp(g.gen, y.value, g.prime)
	return z
}

// RandomCoprime randomly generates coprimes in the group (coprime
// against g.prime-1)
func (g *Group) RandomCoprime(r *Int) *Int {
	g.checkInts(r)
	var err error
	for r.value.Set(g.psub1); !r.value.IsCoprime(g.psub1); {
		g.random, err = csprng.GenerateInGroup(g.prime.Bytes(), len(g.psub1.Bytes()), g.rng)
		if err != nil {
			jww.FATAL.Panicf("Could not generate random "+
				"Coprime number in group: %v", err.Error())
		}
		r.value.SetBytes(g.random)
		r.value.Mod(r.value, g.psub3)
		r.value.Add(r.value, g.two)
	}
	return r
}

// RootCoprime sets tmp = y√x mod p, and returns tmp. Only works with y's
// coprime with g.prime-1 (g.psub1)
func (g Group) RootCoprime(x, y, z *Int) *Int {
	g.checkInts(x, y, z)
	tmp := g.NewInt(1)
	tmp.value.ModInverse(y.value, g.psub1)
	g.Exp(x, tmp, z)
	return z
}

// Finds a number coprime with p-1 and who's modular exponential inverse is
// the number of prescribed bits value. Bits must be greater than 1.
// Only works when the prime is safe or strong
// Using a smaller bytes length is acceptable because modular logarithm algorithm's
// complexities derive primarily from the size of the prime defining the group
// not the size of the exponent.  More information can be found here:
// TODO: add link to doc
// The function will panic if bits >= log2(g.prime), so the caller MUST use
// a correct value of bits

func (g Group) FindSmallCoprimeInverse(z *Int, bitLen uint32) *Int {
	if bitLen >= uint32(g.prime.BitLen()) {
		jww.FATAL.Panicf("Requested bits: %d is greater than"+
			" or equal to group's prime: %d", bitLen, g.prime.BitLen())
	}

	g.checkInts(z)
	// RNG that ensures the output is an odd number between 2 and 2^bitLen
	// that is not equal to p-1/2.  This must occur because for a proper
	// modular inverse to exist within a group a number must have no common
	// factors with the number that defines the group.  Normally that would not
	// be a problem because the number that defines the group normally is a prime,
	// but we are inverting within a group defined by the even number p-1 to find the
	// modular exponential inverse, so the number must be chozen from a different set

	// In order to generate the number in the range
	// the following steps are taken:
	// 1. max = 2^(bitLen)-2
	// 2. gen rand num by reading from rng
	// 3. rand mod max : giving a range of 0 - 2^(bitLen)-3
	// 4. rand + 2: range: 2 - 2^(bitLen)-1
	// 5. rand ^ 1: range: 3 - 2^(bitLen)-1, odd number
	max := large.NewInt(1).Sub(
		large.NewInt(1).LeftShift(
			g.one,
			uint(bitLen)),
		g.two)

	zinv := large.NewInt(1)

	for true {
		n, err := g.rng.Read(g.random)
		if err != nil || n != len(g.random) {
			jww.FATAL.Panicf("Could not generate random "+
				"number in group: %v", err.Error())
		}
		zinv.SetBytes(g.random)
		zinv.Mod(zinv, max)
		zinv.Add(zinv, g.two)
		zinv.Xor(zinv, g.one)

		// p-1 has one odd factor, (p-1)/2,  we must check that the generated number is not that
		if zinv.Cmp(g.psub1factor) == 0 {
			continue
		}

		// Modulo inverse zinv and check that the inverse exists
		if z.value.ModInverse(zinv, g.psub1) == nil {
			continue
		}

		zbytes := z.Bytes()

		// Checks if the lowest bit is 1, implying the value is odd.
		// Due to the fact that p is a safe prime, this means the value is
		// coprime with p minus 1 because its only has one odd factor, which is
		// also checked

		if zbytes[len(zbytes)-1]&0x01 == 1 {
			if zinv.Cmp(g.psub1factor) != 0 {
				break
			}
		}

	}

	return z
}

// GobEncode returns a byte slice representing the encoding of Group for the
// transmission to a GobDecode().
func (g *Group) GobEncode() ([]byte, error) {
	// Anonymous structure that flattens nested structures
	s := struct {
		P []byte
		G []byte
	}{
		g.prime.Bytes(),
		g.gen.Bytes(),
	}

	var buf bytes.Buffer

	// Create new encoder that will transmit the buffer
	enc := gob.NewEncoder(&buf)

	// Transmit the data
	err := enc.Encode(s)

	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// GobDecode overwrites the receiver, which must be a pointer, with Group
// represented by the byte slice, which was written by GobEncode().
func (g *Group) GobDecode(b []byte) error {
	// Anonymous, empty, flat structure
	s := struct {
		P []byte
		G []byte
	}{
		[]byte{},
		[]byte{},
	}

	var buf bytes.Buffer

	// Write bytes to the buffer
	buf.Write(b)

	// Create new decoder that reads from the buffer
	dec := gob.NewDecoder(&buf)

	// Receive and decode data
	err := dec.Decode(&s)

	if err != nil {
		return err
	}

	// Convert decoded bytes and put into empty structure
	prime := large.NewIntFromBytes(s.P)
	gen := large.NewIntFromBytes(s.G)

	*g = *NewGroup(prime, gen)

	return nil
}

// MarshalJSON extracts prime, gen and primeQ to a json object.
// Returns the json object as a byte slice.
func (g *Group) MarshalJSON() ([]byte, error) {

	// Get group parameters
	prime := g.GetP()
	gen := g.GetG()

	// Create json object
	base := 16
	jsonObj := map[string]string{
		"prime": prime.TextVerbose(base, 0),
		"gen":   gen.TextVerbose(base, 0),
	}

	// Marshal json object into byte slice
	b, err := json.Marshal(&jsonObj)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// Overwrites the receiver, which must be a pointer, with Group
// represented by the byte slice which contains encoded JSON data
func (g *Group) UnmarshalJSON(b []byte) error {

	// Initialize json object to contain max sized group params
	base := 16
	max := large.NewMaxInt().TextVerbose(base, 0)
	jsonObj := map[string]string{
		"prime": max,
		"gen":   max,
	}

	// Unmarshal byte slice into json object
	err := json.Unmarshal(b, &jsonObj)

	if err != nil {
		return err
	}

	// Get group params from json object and put into receiver
	prime := large.NewIntFromString(jsonObj["prime"], base)
	gen := large.NewIntFromString(jsonObj["gen"], base)
	*g = *NewGroup(prime, gen)

	return nil
}
