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

// Type Int will implement the above interface by extending big.Int
type Int big.Int

// -------------- Constructors -------------- //

// NewInt allocates and returns a new Int set to x.
func NewInt(x int64) *Int {
	s := new(Int)
	*s = Int(*big.NewInt(x))
	return s
}

// NewIntFromBytes creates a new Int initialized from a byte buffer
func NewIntFromBytes(buf []byte) *Int {
	s := new(Int)
	s.SetBytes(buf)
	return s
}

// NewIntFromString creates a new Int from a string using the passed base
// returns nil if string cannot be parsed
func NewIntFromString(str string, base int) *Int {
	s := new(Int)
	_, b := s.SetString(str, base)
	if b == false {
		return nil
	}
	return s
}

// NewIntFromBigInt allocates and returns a new Int from a big.Int.
func NewIntFromBigInt(x *big.Int) *Int {
	s := new(Int)
	s.SetBigInt(x)
	return s
}

// NewMaxInt creates a new Int with the value Max4KInt
func NewMaxInt() *Int {
	return NewIntFromBytes(Max4kBitInt)
}

// NewIntFromUInt creates a new Int from a uint64
func NewIntFromUInt(i uint64) *Int {
	s := new(Int)
	s.SetUint64(i)
	return s
}

// DeepCopy Creates a deep copy of the large int
func (z *Int) DeepCopy() *Int {
	return NewInt(0).Set(z)
}

// -------------- Setters -------------- //

// Set sets z to x and returns z.
func (z *Int) Set(x *Int) *Int {
	(*big.Int)(z).Set((*big.Int)(x))
	return z
}

// Sets z to bigInt x and returns z.
func (z *Int) SetBigInt(x *big.Int) *Int {
	(*big.Int)(z).Set(x)
	return z
}

// SetString makes the Int equal to the number held in the string s,
// interpreted to have a base of b. Returns the set Int and a boolean
// describing if the operation was successful.
func (z *Int) SetString(s string, base int) (*Int, bool) {
	y := (*big.Int)(z)
	_, b := y.SetString(s, base)
	if b == false {
		return nil, false
	}
	return z, b
}

//SetBytes interprets buf as the bytes of a big-endian unsigned
//integer, sets z to that value, and returns z.
func (z *Int) SetBytes(buf []byte) *Int {
	(*big.Int)(z).SetBytes(buf)
	return z
}

//SetInt64 sets z to the value of the passed int64
func (z *Int) SetInt64(x int64) *Int {
	(*big.Int)(z).SetInt64(x)
	return z
}

//SetUint64 sets z to the value of the passed uint64
func (z *Int) SetUint64(x uint64) *Int {
	(*big.Int)(z).SetUint64(x)
	return z
}

// -------------- Converters -------------- //

// BigInt converts the Int to a *big.Int representation
func (z *Int) BigInt() *big.Int {
	return (*big.Int)(z)
}

// Int64 converts the Int to an Int64 if possible or undefined result if not
func (z *Int) Int64() int64 {
	return (*big.Int)(z).Int64()
}

// Int64 converts the Int to a Uint64 if possible or undefined result if not
func (z *Int) Uint64() uint64 {
	return (*big.Int)(z).Uint64()
}

// IsInt64 checks if an Int can be converted to an Int64
func (z *Int) IsInt64() bool {
	return (*big.Int)(z).IsInt64()
}

// -------------- Basic Arithmetic Operators -------------- //

// Add sets z to the sum x+y and returns z.
func (z *Int) Add(x, y *Int) *Int {
	(*big.Int)(z).Add(
		(*big.Int)(x),
		(*big.Int)(y))
	return z
}

// Sub sets z to the difference x-y and returns z.
func (z *Int) Sub(x, y *Int) *Int {
	(*big.Int)(z).Sub(
		(*big.Int)(x),
		(*big.Int)(y))
	return z
}

// Mul sets z to the product x*y and returns z.
func (z *Int) Mul(x, y *Int) *Int {
	(*big.Int)(z).Mul(
		(*big.Int)(x),
		(*big.Int)(y))
	return z
}

// Div sets z to the quotient x/y and returns z.
func (z *Int) Div(x, y *Int) *Int {
	(*big.Int)(z).Div(
		(*big.Int)(x),
		(*big.Int)(y))
	return z
}

// -------------- Operators with modulo -------------- //

// Mod sets z to the modulus x%y for y != 0 and returns z. If y == 0, a
// division-by-zero run-time panic occurs. Mod implements Euclidean
// modulus (unlike Go); see DivMod for more details.
func (z *Int) Mod(x, y *Int) *Int {
	(*big.Int)(z).Mod(
		(*big.Int)(x),
		(*big.Int)(y))
	return z
}

// ModInverse sets x to the multiplicative inverse of z in the ring
// ℤ/nℤ and returns x.
// If z and n are not relatively prime, the result is nil
func (z *Int) ModInverse(x, n *Int) *Int {
	return (*Int)((*big.Int)(z).ModInverse(
		(*big.Int)(x),
		(*big.Int)(n)))
}

// Exp sets z = x*y mod |m| (i.e. the sign of m is ignored), and
// returns z. If y <= 0, the result is 1 mod |m|; if m == nil or m ==
// 0, z = x*y. Modular exponentation of inputs of a particular size is
// not a cryptographically constant-time operation.
func (z *Int) Exp(x, y, m *Int) *Int {
	(*big.Int)(z).Exp(
		(*big.Int)(x),
		(*big.Int)(y),
		(*big.Int)(m))
	return z
}

// -------------- GCD Operator -------------- //

// GCD returns the greatest common denominator
func (z *Int) GCD(x, y, a, b *Int) *Int {
	(*big.Int)(z).GCD(
		(*big.Int)(x),
		(*big.Int)(y),
		(*big.Int)(a),
		(*big.Int)(b))
	return z
}

// -------------- Misc Operators -------------- //

// IsCoprime returns true if the 2 numbers are coprime (relatively prime)
func (z *Int) IsCoprime(x *Int) bool {
	s := NewInt(0)
	if s.ModInverse(z, x) == nil {
		return false
	}
	return true
}

// IsPrime calculates (with high probability) if a number is prime or not.
// This function uses 40 (can be changed) iterations of the Miller-Rabin prime test
// Return: True if number is prime. False if not.
func (z *Int) IsPrime() bool {
	return (*big.Int)(z).ProbablyPrime(40)
}

// BitLen returns the length of the absolute value of x in bits. The
// bit length of 0 is 0.
func (z *Int) BitLen() int {
	return (*big.Int)(z).BitLen()
}

// Cmp compares x and y and returns:
//	-1 if x < y
//	 0 if x == y
//	+1 if x > y
func (z *Int) Cmp(y *Int) int {
	return (*big.Int)(z).Cmp((*big.Int)(y))
}

// -------------- Bitwise Operators -------------- //

//RightShift shifts the value right by n bits
func (z *Int) RightShift(x *Int, n uint) *Int {
	(*big.Int)(z).Rsh((*big.Int)(x), n)
	return z
}

//LeftShift shifts the value left by n bits
func (z *Int) LeftShift(x *Int, n uint) *Int {
	(*big.Int)(z).Lsh((*big.Int)(x), n)
	return z
}

//Or computes the bitwise or operation between the Cyclic Ints
func (z *Int) Or(x, y *Int) *Int {
	(*big.Int)(z).Or(
		(*big.Int)(x),
		(*big.Int)(y))
	return z
}

//Xor computes the bitwise xor operation between the Cyclic Ints
func (z *Int) Xor(x, y *Int) *Int {
	(*big.Int)(z).Xor(
		(*big.Int)(x),
		(*big.Int)(y))
	return z
}

//And computes the bitwise and operation between the Cyclic Ints
func (z *Int) And(x, y *Int) *Int {
	(*big.Int)(z).And(
		(*big.Int)(x),
		(*big.Int)(y))
	return z
}

// -------------- Byte slice getters -------------- //

// Bytes returns the absolute value of x as a big-endian byte slice.
func (z *Int) Bytes() []byte {
	return (*big.Int)(z).Bytes()
}

// LeftpadBytes returns the absolute value of x leftpadded with zeroes
// up the the passed number of bytes.  Panics if the byte slice from the Int
// is longer than the passed length
func (z *Int) LeftpadBytes(length uint64) []byte {
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
func (z *Int) Text(base int) string {
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
func (z *Int) TextVerbose(base int, length int) string {
	fullText := (*big.Int)(z).Text(base)

	if length == 0 || len(fullText) <= length {
		return fullText
	} else {
		return fullText[:length] + "..."
	}
}

// -------------- GOB Operators -------------- //
// GOB operators
func (z *Int) GobDecode(in []byte) error {
	z.SetBytes(in)
	return nil
}

func (z *Int) GobEncode() ([]byte, error) {
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
