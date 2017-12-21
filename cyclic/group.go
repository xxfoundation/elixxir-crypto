package cyclic

import (
	"errors"
	"fmt"
	"reflect"
)

// Groups provide cyclic int operations that keep the return values confined to
// a finite field under modulo p
type Group struct {
	prime  *Int
	psub1  *Int
	seed   *Int
	random *Int
	one    *Int
	g      Gen
}

// NewGroup returns a group with the given prime, seed, and generator
func NewGroup(p *Int, s *Int, g Gen) Group {
	return Group{p, NewInt(0).Sub(p, NewInt(1)), s, NewInt(0), NewInt(1), g}
}

// Mul multiplies a and b within the group, putting the result in c
// and returning c
func (g *Group) Mul(a, b, c *Int) *Int {
	return c.Mod((c.Mul(a, b)), g.prime)
}

// Inside returns true of the Int is within the group, false if it isn't
func (g *Group) Inside(a *Int) bool {
	if a.Cmp(g.one) == -1 || a.Cmp(g.prime) != -1 {
		return false
	} else {
		return true
	}
}

// Inverse sets b equal to the inverse of a within the group and returns b
func (g *Group) Inverse(a, b *Int) *Int {
	return b.ModInverse(a, g.prime)
}

// SetSeed sets a seed for use in random number generation
func (g *Group) SetSeed(k *Int) {
	g.seed = k
}

// Gen securely generates a random number within the group and sets r
// equal to it.
func (g *Group) Gen(r *Int) *Int {
	r = r.Add(g.seed, g.g.Rand(g.random))
	r = r.Mod(r, g.psub1)
	r = r.Add(r, g.one)
	//println("rand: ", r.Text(10))
	return r
}

// GetP sets the passed Int equal to p
func (g *Group) GetP(p *Int) *Int {
	p.value = g.prime.value
	return p
}

// GroupMul Multiplies all ints in the passed slice slc together and
// places the result in c
func (g Group) GroupMul(slc []*Int, c *Int) *Int {
	err := errors.New("Unimplemented function: Group.GroupMul recieved " +
		reflect.TypeOf(slc).String() + " " + reflect.TypeOf(c).String() + "\n")

	if err != nil {
		fmt.Print(err)
	}

	return nil
}

// Exp sets z = x**y mod p, and returns z.
func (g Group) Exp(x, y, z *Int) *Int {
	err := errors.New("Unimplemented function: Group.Exp recieved " +
		reflect.TypeOf(x).String() + " " + reflect.TypeOf(y).String() +
		reflect.TypeOf(z).String() + "\n")

	if err != nil {
		fmt.Print(err)
	}

	return nil
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
