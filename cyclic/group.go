package cyclic

import (
	"errors"
	"fmt"
	"reflect"
)

// Groups provide cyclic int operations that keep the return values confined to
// a finite field under modulo p
type Group struct {
	prime *Int
	seed  *Int
	g     Gen
}

// NewGroup returns a group with the given prime, seed, and generator
func NewGroup(p *Int, s *Int, g Gen) Group {
	return Group{p, s, g}
}

// Mul multiplies a and b within the group, putting the result in c
// and returning c
func (g Group) Mul(a, b, c *Int) *Int {
	return c.Mod((c.Mul(a, b)), g.prime)
}

// Inside returns true of the Int is within the group, false if it isn't
func (g Group) Inside(a *Int) bool {
	if a.Cmp(NewInt(0)) != 1 || a.Cmp(g.prime) != -1 {
		return false
	} else {
		return true
	}
}

// Inverse sets b equal to the inverse of a within the group and returns b
func (g Group) Inverse(a, b *Int) *Int {
	return b.ModInverse(a, g.prime)
}

// SetSeed sets a seed for use in random number generation
func (g Group) SetSeed(k *Int) {
	err := errors.New("Unimplemented function: Group.SetK recieved " +
		reflect.TypeOf(k).String() + "\n")

	if err != nil {
		fmt.Print(err)
	}

}

// Gen securely generates a random number within the group and sets r
// equal to it.
func (g Group) Gen(r *Int) *Int {
	err := errors.New("Unimplemented function: Group.Gen recieved " +
		reflect.TypeOf(r).String() + "\n")

	if err != nil {
		fmt.Print(err)
	}

	return nil
}

// GetP sets the passed Int equal to p
func (g Group) GetP(p *Int) *Int {
	err := errors.New("Unimplemented function: Group.GetP recieved " +
		reflect.TypeOf(p).String() + "\n")

	if err != nil {
		fmt.Print(err)
	}

	return nil
}

// GroupMul Multiplies all ints in the passed slice slc together and
// places the result in c
func (g Group) ArrayMul(slc []*Int, c *Int) *Int {

	c.SetString("1", 10)

	for _, islc := range slc {
		g.Mul(c, islc, c)
	}

	return c
}

// Exp sets z = x**y mod p, and returns z.
func (g Group) Exp(x, y, z *Int) *Int {

	return z.Exp(x, y, g.prime)
}

// Root sets z = y√x mod p, and returns z.
func (g Group) Root(x, y, z *Int) *Int {
	err := errors.New("Unimplemented function: Group.Root recieved " +
		reflect.TypeOf(x).String() + " " + reflect.TypeOf(y).String() +
		reflect.TypeOf(z).String() + "\n")

	if err != nil {
		fmt.Print(err)
	}

	return nil
}

//nilGroup returns a nil group
func nilGroup() *Group {
	return nil
}
