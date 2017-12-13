package cyclic

import (
	"errors"
	"fmt"
	"math/big"
	"reflect"
)

//Create the cyclic.Int type as a wrapper of the big.Int type
type Int big.Int

//Int64 converts the cyclic Int to an Int64 if possible and returns nil if not
func (n *Int) Int64() int64 {
	return bigInt(n).Int64()
}

//IsInt64 checks if a cyclic Int can be converted to an Int64
func (n *Int) IsInt64() bool {
	return bigInt(n).IsInt64()
}

//NewInt allocates and returns a new Int set to x.
func NewInt(x int64) *Int {

	b := big.NewInt(x)
	c := Int(*b)

	return &c
}


//SetString makes the Int equal to the number held in the string s,
//interpreted to have a base of b. Returns the set Int and a boolean
//describing if the operation was successful.
func (c *Int) SetString(s string, x int) (*Int, bool) {
	success := false
	b := big.NewInt(0)
	b, success = b.SetString(s, x)
	*c = Int(*b)
	return c, success

//Set sets z to x and returns z.
func (z *Int) Set(x *Int) *Int {
	b := bigInt(z).Set(bigInt(x))
	c := Int(*b)

	return &c
}

}

//SetBytes interprets buf as the bytes of a big-endian unsigned
//integer, sets z to that value, and returns z.
func (c *Int) SetBytes(buf []byte) *Int {
	b := big.NewInt(0)
	b = b.SetBytes(buf)
	*c = Int(*b)
	return c


//Mod sets z to the modulus x%y for y != 0 and returns z. If y == 0, a
//division-by-zero run-time panic occurs. Mod implements Euclidean
//modulus (unlike Go); see DivMod for more details.
func (z *Int) Mod(x, m *Int) *Int {

	b := bigInt(z).Mod(bigInt(x), bigInt(m))
	c := Int(*b)

	return &c
}

//ModInverse sets z to the multiplicative inverse of g in the ring
//ℤ/nℤ and returns z. If g and n are not relatively prime, the result is
//undefined.
func (z *Int) ModInverse(g, n *Int) *Int {
	b := bigInt(z).ModInverse(bigInt(g), bigInt(n))
	c := Int(*b)

	return &c
}

//Add sets z to the sum x+y and returns z.
func (z *Int) Add(x, y *Int) *Int {
	b := bigInt(z).Add(bigInt(x), bigInt(y))
	c := Int(*b)
	return &c
}

//Mul sets z to the product x*y and returns z.
func (z *Int) Mul(x, y *Int) *Int {
	b := bigInt(z).Mul(bigInt(x), bigInt(y))
	c := Int(*b)

	return &c
}

//Exp sets z = x*y mod |m| (i.e. the sign of m is ignored), and
//returns z. If y <= 0, the result is 1 mod |m|; if m == nil or m ==
//0, z = x*y. Modular exponentation of inputs of a particular size is
//not a cryptographically constant-time operation.
func (z *Int) Exp(x, y, m *Int) *Int {

	b := bigInt(z).Exp(bigInt(x), bigInt(y), bigInt(m))
	c := Int(*b)

	return &c

}

//Bytes returns the absolute value of x as a big-endian byte slice.
func (x *Int) Bytes() []byte {

	return bigInt(x).Bytes()
}

//BitLen returns the length of the absolute value of x in bits. The
//bit length of 0 is 0.
func (x *Int) BitLen() int {
	return bigInt(x).BitLen()

}

//Cmp compares x and y and returns:
//	-1 if x < y
//	 0 if x == y
//	+1 if x > y
func (x *Int) Cmp(y *Int) (r int) {
	return bigInt(x).Cmp(bigInt(y))
}

//Text returns the string representation of x in the given base. Base
//must be between 2 and 36, inclusive. The result uses the lower-case
//letters 'a' to 'z' for digit values >= 10. No base prefix (such as
//"0x") is added to the string.
func (x *Int) Text(base int) string {

	return bigInt(x).Text(base)

}

//PRIVATE FUNCTIONS

//bigInt converts the givne cyclic Int to a big Int and returns it
func bigInt(n *Int) *big.Int {
	nint := big.Int(*n)
	return &nint
}

//nilInt returns a cyclic Int which is nil
func nilInt() *Int {
	return nil
}
