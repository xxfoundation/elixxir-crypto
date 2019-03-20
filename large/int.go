////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package large

import (
	jww "github.com/spf13/jwalterweatherman"
	"math/big"
)


// The big.Int type from go almost conforms to this interface
// Some methods don't exist, so the big.Int implementation is extended
// in this package
type Int interface {
	// Setters
	Set(x Int) Int
	SetBigInt(x *big.Int) Int
	SetString(s string, base int) (Int, bool)
	SetBytes(buf []byte) Int
	SetInt64(x int64) Int
	SetUint64(x uint64) Int
	// Converters
	BigInt() *big.Int
	Int64() int64
	Uint64() uint64
	IsInt64() bool
	// Basic Arithmetic Operators
	Add(x, y Int) Int
	Sub(x, y Int) Int
	Mul(x, y Int) Int
	Div(x, y Int) Int
	// Operators with modulo
	Mod(x, m Int) Int
	ModInverse(z, m Int) Int
	Exp(x, y, m Int) Int
	// GCD Operator
	GCD(x, y, a, b Int) Int
	// Misc Operators
    IsCoprime(x Int) bool
	IsPrime() bool
	BitLen() int
	Cmp(y Int) int
	// Bitwise Operators
	RightShift(x Int, n uint) Int
	LeftShift(x Int, n uint) Int
	Or(x, y Int) Int
	Xor(x, y Int) Int
	And(x, y Int) Int
	// Byte slice getters
	Bytes() []byte
	LeftpadBytes(length uint64) []byte
	// String representation getters
	Text(base int) string
	TextVerbose(base int, length int) string
	// GOB Operators
    GobDecode(in []byte) error
    GobEncode() ([]byte, error)
}

// Type largeInt will implement the above interface by extending big.Int
type largeInt big.Int

// -------------- Constructors -------------- //

// NewInt allocates and returns a new Int set to x.
func NewInt(x int64) Int {
	s := new(largeInt)
	*s = largeInt(*big.NewInt(x))
	return s
}

// NewIntFromBytes creates a new Int initialized from a byte buffer
func NewIntFromBytes(buf []byte) Int {
	s := new(largeInt)
	return s.SetBytes(buf)
}

// NewIntFromString creates a new Int from a string using the passed base
// returns nil if string cannot be parsed
func NewIntFromString(str string, base int) Int {
	s := new(largeInt)
	_, b := s.SetString(str, base)
	if b == false {
		return nil
	}
	return s
}

// NewIntFromBigInt allocates and returns a new Int from a big.Int.
func NewIntFromBigInt(x *big.Int) Int {
	s := new(largeInt)
	s.SetBigInt(x)
	return s
}

// NewMaxInt creates a new Int with the value Max4KInt
func NewMaxInt() Int {
	return NewIntFromBytes(Max4kBitInt)
}

// NewIntFromUInt creates a new Int from a uint64
func NewIntFromUInt(i uint64) Int {
	s := new(largeInt)
	return s.SetUint64(i)
}

// -------------- Setters -------------- //

// Set sets z to x and returns z.
func (z *largeInt) Set(x Int) Int {
	*z = *x.(*largeInt)
	return z
}

// Sets z to bigInt x and returns z.
func (z *largeInt) SetBigInt(x *big.Int) Int {
	*z = largeInt(*x)
	return z
}

// SetString makes the Int equal to the number held in the string s,
// interpreted to have a base of b. Returns the set Int and a boolean
// describing if the operation was successful.
func (z *largeInt) SetString(s string, base int) (Int, bool) {
	var y big.Int
	_, b := y.SetString(s, base)
	if b == false {
		return nil, false
	}
	*z = largeInt(y)
	return z, b
}

//SetBytes interprets buf as the bytes of a big-endian unsigned
//integer, sets z to that value, and returns z.
func (z *largeInt) SetBytes(buf []byte) Int {
	var y big.Int
	*z = largeInt(*y.SetBytes(buf))
	return z
}

//SetInt64 sets z to the value of the passed int64
func (z *largeInt) SetInt64(x int64) Int {
	var y big.Int
	*z = largeInt(*y.SetInt64(x))
	return z
}

//SetUint64 sets z to the value of the passed uint64
func (z *largeInt) SetUint64(x uint64) Int {
	var y big.Int
	*z = largeInt(*y.SetUint64(x))
	return z
}

// -------------- Converters -------------- //

// BigInt converts the Int to a *big.Int representation
func (z *largeInt) BigInt() *big.Int {
	return (*big.Int)(z)
}

// Int64 converts the Int to an Int64 if possible or undefined result if not
func (z *largeInt) Int64() int64 {
	return (*big.Int)(z).Int64()
}

// Int64 converts the Int to a Uint64 if possible or undefined result if not
func (z *largeInt) Uint64() uint64 {
	return (*big.Int)(z).Uint64()
}

// IsInt64 checks if an Int can be converted to an Int64
func (z *largeInt) IsInt64() bool {
	return (*big.Int)(z).IsInt64()
}

// -------------- Basic Arithmetic Operators -------------- //

// Add sets z to the sum x+y and returns z.
func (z *largeInt) Add(x, y Int) Int {
	var a big.Int
	*z = largeInt(*a.Add(
		(*big.Int)(x.(*largeInt)),
		(*big.Int)(y.(*largeInt))))
	return z
}

// Sub sets z to the difference x-y and returns z.
func (z *largeInt) Sub(x, y Int) Int {
	var a big.Int
	*z = largeInt(*a.Sub(
		(*big.Int)(x.(*largeInt)),
		(*big.Int)(y.(*largeInt))))
	return z
}

// Mul sets z to the product x*y and returns z.
func (z *largeInt) Mul(x, y Int) Int {
	var a big.Int
	*z = largeInt(*a.Mul(
		(*big.Int)(x.(*largeInt)),
		(*big.Int)(y.(*largeInt))))
	return z
}

// Div sets z to the quotient x/y and returns z.
func (z *largeInt) Div(x, y Int) Int {
	var a big.Int
	*z = largeInt(*a.Div(
		(*big.Int)(x.(*largeInt)),
		(*big.Int)(y.(*largeInt))))
	return z
}

// -------------- Operators with modulo -------------- //

// Mod sets z to the modulus x%y for y != 0 and returns z. If y == 0, a
// division-by-zero run-time panic occurs. Mod implements Euclidean
// modulus (unlike Go); see DivMod for more details.
func (z *largeInt) Mod(x, y Int) Int {
	var a big.Int
	*z = largeInt(*a.Mod(
		(*big.Int)(x.(*largeInt)),
		(*big.Int)(y.(*largeInt))))
	return z
}

// ModInverse sets x to the multiplicative inverse of z in the ring
// ℤ/nℤ and returns x.
// If z and n are not relatively prime, the result is nil
func (x *largeInt) ModInverse(z, n Int) Int {
	var a big.Int
	rtn := a.ModInverse(
		(*big.Int)(z.(*largeInt)),
		(*big.Int)(n.(*largeInt)))
	if rtn == nil {
		return nil
	}
	*x = largeInt(a)
	return x
}

// Exp sets z = x*y mod |m| (i.e. the sign of m is ignored), and
// returns z. If y <= 0, the result is 1 mod |m|; if m == nil or m ==
// 0, z = x*y. Modular exponentation of inputs of a particular size is
// not a cryptographically constant-time operation.
func (z *largeInt) Exp(x, y, m Int) Int {
	var a big.Int
	*z = largeInt(*a.Exp(
		(*big.Int)(x.(*largeInt)),
		(*big.Int)(y.(*largeInt)),
		(*big.Int)(m.(*largeInt))))
	return z
}

// -------------- GCD Operator -------------- //

// GCD returns the greatest common denominator
func (z *largeInt) GCD(x, y, a, b Int) Int {
	var c big.Int
	*z = largeInt(*c.GCD(
		(*big.Int)(x.(*largeInt)),
		(*big.Int)(y.(*largeInt)),
		(*big.Int)(a.(*largeInt)),
		(*big.Int)(b.(*largeInt))))
	return z
}

// -------------- Misc Operators -------------- //

// IsCoprime returns true if the 2 numbers are coprime (relatively prime)
func (z *largeInt) IsCoprime(x Int) bool {
	s := NewInt(0)
	if s.ModInverse(z, x) == nil {
		return false
	}
	return true
}

// IsPrime calculates (with high probability) if a number is prime or not.
// This function uses 40 (can be changed) iterations of the Miller-Rabin prime test
// Return: True if number is prime. False if not.
func (z *largeInt) IsPrime() bool {
	return (*big.Int)(z).ProbablyPrime(40)
}

// BitLen returns the length of the absolute value of x in bits. The
// bit length of 0 is 0.
func (z *largeInt) BitLen() int {
	return (*big.Int)(z).BitLen()
}

// Cmp compares x and y and returns:
//	-1 if x < y
//	 0 if x == y
//	+1 if x > y
func (z *largeInt) Cmp(y Int) (r int) {
	return (*big.Int)(z).Cmp((*big.Int)(y.(*largeInt)))
}

// -------------- Bitwise Operators -------------- //

//RightShift shifts the value right by n bits
func (z *largeInt) RightShift(x Int, n uint) Int {
	var a big.Int
	*z = largeInt(*a.Rsh(
		(*big.Int)(x.(*largeInt)),
		n))
	return z
}

//LeftShift shifts the value left by n bits
func (z *largeInt) LeftShift(x Int, n uint) Int {
	var a big.Int
	*z = largeInt(*a.Lsh(
		(*big.Int)(x.(*largeInt)),
		n))
	return z
}

//Or computes the bitwise or operation between the Cyclic Ints
func (z *largeInt) Or(x, y Int) Int {
	var a big.Int
	*z = largeInt(*a.Or(
		(*big.Int)(x.(*largeInt)),
		(*big.Int)(y.(*largeInt))))
	return z
}

//Xor computes the bitwise xor operation between the Cyclic Ints
func (z *largeInt) Xor(x, y Int) Int {
	var a big.Int
	*z = largeInt(*a.Xor(
		(*big.Int)(x.(*largeInt)),
		(*big.Int)(y.(*largeInt))))
	return z
}

//And computes the bitwise and operation between the Cyclic Ints
func (z *largeInt) And(x, y Int) Int {
	var a big.Int
	*z = largeInt(*a.And(
		(*big.Int)(x.(*largeInt)),
		(*big.Int)(y.(*largeInt))))
	return z
}

// -------------- Byte slice getters -------------- //

// Bytes returns the absolute value of x as a big-endian byte slice.
func (z *largeInt) Bytes() []byte {
	return (*big.Int)(z).Bytes()
}

// LeftpadBytes returns the absolute value of x leftpadded with zeroes
// up the the passed number of bytes.  Panics if the byte slice from the Int
// is longer than the passed length
func (z *largeInt) LeftpadBytes(length uint64) []byte {
	b := z.Bytes()

	if uint64(len(b)) > length {
		jww.FATAL.Panicf("large.Int.LeftpadBytes("+
			"): Byte array too long! Expected: %v, Received: %v", length, len(b))
	}

	rtnslc := make([]byte, length-uint64(len(b)))

	rtnslc = append(rtnslc, b...)

	return rtnslc
}

// -------------- String representation getters -------------- //

// Text returns the string representation of z in the given base. Base
// must be between 2 and 36, inclusive. The result uses the lower-case
// letters 'a' to 'z' for digit values >= 10. No base prefix (such as
// "0x") is added to the string.
// Text truncates ints to a length of 10, appending an ellipsis
// if the int is too long.
func (z *largeInt) Text(base int) string {
	const intTextLen = 10
	return z.TextVerbose(base, intTextLen)
}

// TextVerbose returns the string representation of z in the given base. Base
// must be between 2 and 36, inclusive. The result uses the lower-case
// letters 'a' to 'z' for digit values >= 10. No base prefix (such as
// "0x") is added to the string.
// TextVerbose truncates ints to a length of length in characters (not runes)
// and append an ellipsis to indicate that the whole int wasn't returned,
// unless len is 0, in which case it will return the whole int as a string.
func (z *largeInt) TextVerbose(base int, length int) string {
	fullText := (*big.Int)(z).Text(base)

	if length == 0 || len(fullText) <= length {
		return fullText
	} else {
		return fullText[:length] + "..."
	}
}

// -------------- GOB Operators -------------- //
// GOB operators
func (z *largeInt) GobDecode(in []byte) error {
	z.SetBytes(in)
	return nil
}

func (z *largeInt) GobEncode() ([]byte, error) {
	return z.Bytes(), nil
}

// CONSTANTS

// A 4128bit int, meant to be the size of post moded cyclic ints.
// Will probably be made to hold this 4096 bit prime:
//   https://tools.ietf.org/html/rfc3526#page-5
var Max4kBitInt = []byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
