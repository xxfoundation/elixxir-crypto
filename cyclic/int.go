package cyclic

import (
	"math/big"
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

// Int64 converts the cyclic Int to an Int64 if possible and returns nil if not
func (n *Int) Int64() int64 {
	return n.value.Int64()
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

// ModInverse sets z to the multiplicative inverse of g in the ring
// ℤ/nℤ and returns z. If g and n are not relatively prime, the result is
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

// Sub sets z to the difference x-y and returns z.
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

// Bytes returns the absolute value of x as a big-endian byte slice.
func (x *Int) Bytes() []byte {
	return x.value.Bytes()
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
func (x *Int) Text(base int) string {
	return x.value.Text(base)
}

//PRIVATE

// bigInt converts the givne cyclic Int to a big Int and returns it's pointer
func bigInt(n *Int) *big.Int {
	b := big.NewInt(0)
	b.Set(n.value)
	return b
}

// cycInt converts the given big Int to a cyc Int and returns it's pointer
func cycInt(n *big.Int) *Int {
	c := Int(*n)
	return &c
}

// nilInt returns a cyclic Int which is nil
func nilInt() *Int {
	return nil
}