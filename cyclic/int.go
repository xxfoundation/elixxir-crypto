package cyclic

import (
	"math/big"
	"fmt"
)

// Create the cyclic.Int type as a wrapper of the big.Int type
type Int struct {
	value *big.Int
}

// NewInt allocates and returns a new Int set to x.
func NewInt(x int64) *Int {
	s := new(Int)
	s.value = big.NewInt(x)
	return s
}

// NewIntFromBytes creates a new Int initialized from a byte buffer
func NewIntFromBytes(buf []byte) *Int {
	s := new(Int)
	var x big.Int
	x.SetBytes(buf)
	s.value = &x
	return s
}

// NewIntFromString creates a new Int from a string using the passed base
func NewIntFromString(str string, base int) *Int {
	s := new(Int)
	var x big.Int
	x.SetString(str, base)
	s.value = &x
	return s
}

// NewMaxInt creates a new Int with the value Max4KInt
func NewMaxInt() *Int {
	s := new(Int)
	var x big.Int
	x.SetBytes(Max4kBitInt)
	s.value = &x
	return s
}

// NewIntFromUInt creates a new Int from a uint64
func NewIntFromUInt(i uint64) *Int {
	s := new(Int)
	var x big.Int
	x.SetUint64(i)
	s.value = &x
	return s
}

// Set sets z to x and returns z.
func (z *Int) Set(x *Int) *Int {
	z.value.Set(x.value)
	return z
}

// SetString makes the Int equal to the number held in the string s,
// interpreted to have a base of b. Returns the set Int and a boolean
// describing if the operation was successful.
func (c *Int) SetString(s string, x int) (*Int, bool) {
	var b bool
	_, b = c.value.SetString(s, x)
	if b == false {
		return nil, false
	}
	return c, b
}

//SetBytes interprets buf as the bytes of a big-endian unsigned
//integer, sets z to that value, and returns z.
func (c *Int) SetBytes(buf []byte) *Int {
	c.value.SetBytes(buf)
	return c
}

//SetBigInt sets the internal Big Int of the Int equal to the value
//of the passed Big Int
func (c *Int) SetBigInt(b *big.Int) *Int {
	c.value.Set(b)
	return c
}

//SetInt64 sets the internal Big Int to the value of the passed int64
func (c *Int) SetInt64(newValue int64) *Int {
	c.value.SetInt64(newValue)
	return c
}

//SetUint64 sets the internal Big Int to the value of the passed uint64
func (c *Int) SetUint64(newValue uint64) *Int {
	c.value.SetUint64(newValue)
	return c
}

// Int64 converts the cyclic Int to an Int64 if possible and returns nil if not
func (n *Int) Int64() int64 {
	return n.value.Int64()
}

// Int64 converts the cyclic Int to a Uint64 if possible and returns nil if not
func (n *Int) Uint64() uint64 {
	return n.value.Uint64()
}

// IsInt64 checks if a cyclic Int can be converted to an Int64
func (n *Int) IsInt64() bool {
	return n.value.IsInt64()
}

// Mod sets z to the modulus x%y for y != 0 and returns z. If y == 0, a
// division-by-zero run-time panic occurs. Mod implements Euclidean
// modulus (unlike Go); see DivMod for more details.
func (z *Int) Mod(x, m *Int) *Int {
	z.value.Mod(x.value, m.value)
	return z
}

// ModInverse sets x to the multiplicative inverse of z in the ring
// ℤ/nℤ and returns x. If rng and n are not relatively prime, the result is
// undefined.
func (x *Int) ModInverse(z, m *Int) *Int {
	x.value.ModInverse(z.value, m.value)
	return x
}

// Add sets z to the sum x+y and returns z.
func (z *Int) Add(x, y *Int) *Int {
	z.value.Add(x.value, y.value)
	return z
}

// Sub sets z to the difference x-y and returns z.
func (z *Int) Sub(x, y *Int) *Int {
	z.value.Sub(x.value, y.value)
	return z
}

// Mul sets z to the product x*y and returns z.
func (z *Int) Mul(x, y *Int) *Int {
	z.value.Mul(x.value, y.value)
	return z
}

// Div sets z to the quotient x/y and returns z.
func (z *Int) Div(x, y *Int) *Int {
	z.value.Div(x.value, y.value)
	return z
}

// Exp sets z = x*y mod |m| (i.e. the sign of m is ignored), and
// returns z. If y <= 0, the result is 1 mod |m|; if m == nil or m ==
// 0, z = x*y. Modular exponentation of inputs of a particular size is
// not a cryptographically constant-time operation.
func (z *Int) Exp(x, y, m *Int) *Int {
	z.value.Exp(x.value, y.value, m.value)
	return z
}

// GCD returns the greatest common denominator
func (z *Int) GCD(x, y, a, b *Int) *Int {
	var xVal, yVal *big.Int
	if x != nil {
		xVal = x.value
	}
	if y != nil {
		yVal = y.value
	}
	z.value.GCD(xVal, yVal, a.value, b.value)
	return z
}

// IsCoprime returns true if the 2 numbers are coprime (relatively prime)
func (z *Int) IsCoprime(x *Int) bool {
	s := NewInt(0)
	s.GCD(nil, nil, z, x)
	return s.Cmp(NewInt(1)) == 0
}

// Function that calculates (with high probability) if a number is prime or not.
// This function uses 40 (can be changed) iterations of the Miller-Rabin prime test
// Return: True if number is prime. False if not.
func (x *Int) IsPrime() bool {
	return x.value.ProbablyPrime(40)
}

// Bytes returns the absolute value of x as a big-endian byte slice.
func (x *Int) Bytes() []byte {
	return x.value.Bytes()
}

// LeftpadBytes returns the absolute value of x leftpadded with zeroes
// up the the passed number of bytes.  Panics if the byte slice from the Int
// is longer than the passed length
func (x *Int) LeftpadBytes(length uint64) []byte {
	b := x.value.Bytes()

	if uint64(len(b)) > length {
		panic(fmt.Sprintf("Cyclic.Int.BytesAtLen(): Byte array too long! \n"+
			"  Expected: %v, Received: %v", length, len(b)))
	}

	rtnslc := make([]byte, length-uint64(len(b)))

	rtnslc = append(rtnslc, b...)

	return rtnslc
}

// BitLen returns the length of the absolute value of x in bits. The
// bit length of 0 is 0.
func (x *Int) BitLen() int {
	return x.value.BitLen()
}

// Cmp compares x and y and returns:
//	-1 if x < y
//	 0 if x == y
//	+1 if x > y
func (x *Int) Cmp(y *Int) (r int) {
	return x.value.Cmp(y.value)
}

// Text returns the string representation of x in the given base. Base
// must be between 2 and 36, inclusive. The result uses the lower-case
// letters 'a' to 'z' for digit values >= 10. No base prefix (such as
// "0x") is added to the string.
// Text truncates ints to a length of 10, appending an ellipsis
// if the int is too long.
func (x *Int) Text(base int) string {
	const intTextLen = 10
	return x.TextVerbose(base, intTextLen)
}

// TextVerbose returns the string representation of x in the given base. Base
// must be between 2 and 36, inclusive. The result uses the lower-case
// letters 'a' to 'z' for digit values >= 10. No base prefix (such as
// "0x") is added to the string.
// TextVerbose truncates ints to a length of length in characters (not runes)
// and append an ellipsis to indicate that the whole int wasn't returned,
// unless len is 0, in which case it will return the whole int as a string.
func (x *Int) TextVerbose(base int, length int) string {
	fullText := x.value.Text(base)

	if length == 0 || len(fullText) <= length {
		return fullText
	} else {
		return fullText[:length] + "..."
	}
}

func (x *Int) GobDecode(in []byte) error{
    if x.value == nil {
        x.value = big.NewInt(0)
    }
	x.value.SetBytes(in)
	return nil
}

func (x *Int) GobEncode()([]byte,error){
	return x.value.Bytes(), nil
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

// PRIVATE

// bigInt converts the givne cyclic Int to a big Int and returns it's pointer
func bigInt(n *Int) *big.Int {
	b := big.NewInt(0)
	b.Set(n.value)
	return b
}

// cycInt converts the given big Int to a cyc Int and returns it's pointer
func cycInt(n *big.Int) *Int {
	c := new(Int)
	c.value = n
	return c
}
