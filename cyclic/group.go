package cyclic

import (
	"errors"
	"fmt"
	"reflect"
)

// Groups provide cyclic int operations that keep the return values confined to
// a finite field under modulo p
type Group struct {
	prime Int
	seed  Int
	g     Gen
}

// NewGroup returns a group with the given prime, seed, and generator
func NewGroup(p *Int, gen Gen) *Group {
	err := errors.New("Unimplemented function: Group.NewGroup recieved " +
		reflect.TypeOf(p).String() + " " + reflect.TypeOf(gen).String() + "\n")

	if err != nil {
		fmt.Print(err)
	}

	return nil
}

// Mul multiplies a and b within the group, putting the result in c
// and returning c
func (g Group) Mul(a, b, c *Int) *Int {
	err := errors.New("Unimplemented function: Group.Mul recieved " +
		reflect.TypeOf(a).String() + " " + reflect.TypeOf(b).String() +
		reflect.TypeOf(c).String() + "\n")

	if err != nil {
		fmt.Print(err)
	}

	return nil
}

// Inside returns true of the Int is within the group, false if it isn't
func (g Group) Inside(a *Int) bool {
	err := errors.New("Unimplemented function: Group.Inside recieved " +
		reflect.TypeOf(a).String() + "\n")

	if err != nil {
		fmt.Print(err)
	}

	return false
}

// Inverse sets b equal to the inverse of a within the group and returns b
func (g Group) Inverse(a, b *Int) *Int {
	err := errors.New("Unimplemented function: Group.Inverse recieved " +
		reflect.TypeOf(a).String() + " " + reflect.TypeOf(b).String() + "\n")

	if err != nil {
		fmt.Print(err)
	}

	return nil
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
