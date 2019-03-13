////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package cyclic

import (
	jww "github.com/spf13/jwalterweatherman"
)

// Groups provide cyclic int operations that keep the return values confined to
// a finite field under modulo p
//TODO: EVENTUALLY WE NEED TO UPDATE THIS STRUCT AND REMOVE RAND, SEED, RNG, ETC... this is way too complex
type Group struct {
	prime       *Int
	psub1       *Int
	psub2       *Int
	psub3       *Int
	psub1factor *Int
	seed        *Int
	random      *Int
	zero        *Int
	one         *Int
	two         *Int
	G           *Int
	rng         Random
}

// NewGroup returns a group with the given prime, seed, and generator
func NewGroup(p *Int, s *Int, g *Int, rng Random) Group {
	return Group{
		prime:       p,
		psub1:       NewInt(0).Sub(p, NewInt(1)),
		psub2:       NewInt(0).Sub(p, NewInt(2)),
		psub3:       NewInt(0).Sub(p, NewInt(3)),
		psub1factor: NewInt(0).RightShift(NewInt(0).Sub(p, NewInt(1)), 1),

		seed:   s,
		random: NewInt(0),
		zero:   NewInt(0),
		one:    NewInt(1),
		two:    NewInt(2),
		G:      g,
		rng:    rng,
	}
}

// Mul multiplies a and b within the group, putting the result in c
// and returning c
func (g *Group) Mul(a, b, c *Int) *Int {
	return c.Mod(c.Mul(a, b), g.prime)
}

// Inside returns true of the Int is within the group, false if it isn't
func (g *Group) Inside(a *Int) bool {
	return a.Cmp(g.zero) == 1 && a.Cmp(g.prime) == -1
}

// ModP sets z ≡ x mod prime within the group and returns z.
func (g Group) ModP(x, z *Int) *Int {
	z.Mod(x, g.prime)

	return z
}

// Inverse sets b equal to the inverse of a within the group and returns b
func (g *Group) Inverse(a, b *Int) *Int {
	return b.ModInverse(a, g.prime)
}

// SetSeed sets a seed for use in random number generation
func (g *Group) SetSeed(k *Int) {
	g.seed = k
}

// Random securely generates a random number within the group and sets r
// equal to it.
func (g *Group) Random(r *Int) *Int {
	r = r.Add(g.seed, g.rng.Rand(g.random))
	r = r.Mod(r, g.psub2)
	r = r.Add(r, g.two)
	if !g.Inside(r) {
		jww.FATAL.Panicf("Random int is not in cyclic group: %s",
			r.TextVerbose(16, 0))
	}
	return r
}

// GetP sets the passed Int equal to p
// If p is nil we return the pointer. Otherwise we copy the value into p
func (g *Group) GetP(p *Int) *Int {
	g.Copy(p, g.prime)
	return g.prime
}

// GetP sets the passed Int equal to p
func (g *Group) GetPSub1(p *Int) *Int {
	g.Copy(p, g.psub1)
	return g.psub1
}

// Copy returns a copy of the source value to a specific destination var
func (g *Group) Copy(destination, source *Int) {
	if destination != nil {
		destination.value.Set(source.value)
	}
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

// RandomCoprime randomly generates coprimes in the group (coprime
// against g.prime-1)
func (g *Group) RandomCoprime(r *Int) *Int {
	for r.Set(g.psub1); !r.IsCoprime(g.psub1); {
		r.Set(g.one)
		r = r.Add(g.seed, g.rng.Rand(g.random))
		r = r.Mod(r, g.psub3)
		r = r.Add(r, g.two)
	}
	return r
}

// RootCoprime sets z = y√x mod p, and returns z. Only works with y's
// coprime with g.prime-1 (g.psub1)
func (g Group) RootCoprime(x, y, z *Int) *Int {
	z.ModInverse(y, g.psub1)
	g.Exp(x, z, z)
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

func (g Group) FindSmallCoprimeInverse(z *Int, bits uint32) *Int {
	if bits >= uint32(g.prime.BitLen()) {
		jww.FATAL.Panicf("Requested bits: %d is greater than"+
			" or equal to group's prime: %d", bits, g.prime.BitLen())
	}

	// RNG that ensures the output is an odd number between 2 and 2^(
	// bit*8) that is not equal to p-1/2.  This must occur because for a proper
	// modular inverse to exist within a group a number must have no common
	// factors with the number that defines the group.  Normally that would not
	// be a problem because the number that defines the group normally is a prime,
	// but we are inverting within a group defined by the even number p-1 to find the
	// modular exponential inverse, so the number must be chozen from a different set
	max := NewInt(0).Sub(NewInt(0).LeftShift(NewInt(1), uint(bits)-2), NewInt(1))
	rng := NewRandom(NewInt(2), max)

	for true {
		zinv := NewInt(0).Or(NewInt(0).LeftShift(rng.Rand(NewInt(0)), 1), NewInt(1))

		// p-1 has one odd factor, (p-1)/2,  we must check that the generated number is not that
		if zinv.Cmp(g.psub1factor) == 0 {
			continue
		}

		if z.ModInverse(zinv, g.psub1) == nil {
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
