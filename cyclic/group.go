package cyclic

import (
	jww "github.com/spf13/jwalterweatherman"
)

// Groups provide cyclic int operations that keep the return values confined to
// a finite field under modulo p
type Group struct {
	prime  *Int
	psub1  *Int
	psub2  *Int
	psub3  *Int
	seed   *Int
	random *Int
	zero   *Int
	one    *Int
	two    *Int
	G      *Int
	rng    Random
}

// NewGroup returns a group with the given prime, seed, and generator
func NewGroup(p *Int, s *Int, g *Int, rng Random) Group {
	if !p.IsPrime() {
		panic("passed number for NewGroup is not prime")
	}
	return Group{
		prime:  p,
		psub1:  NewInt(0).Sub(p, NewInt(1)),
		psub2:  NewInt(0).Sub(p, NewInt(2)),
		psub3:  NewInt(0).Sub(p, NewInt(3)),
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
func (g *Group) GetP(p *Int) *Int {
	p.value = g.prime.value
	return p
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
