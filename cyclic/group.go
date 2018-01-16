package cyclic

// Groups provide cyclic int operations that keep the return values confined to
// a finite field under modulo p
type Group struct {
	prime  *Int
	psub2  *Int
	seed   *Int
	random *Int
	one    *Int
	two    *Int
	G      *Int
	rng    Random
}

// NewGroup returns a group with the given prime, seed, and generator
func NewGroup(p *Int, s *Int, g *Int, rng Random) Group {
	return Group{p, NewInt(0).Sub(p, NewInt(2)), s, NewInt(0), NewInt(1), NewInt(2), g, rng}
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

// Random securely generates a random number within the group and sets r
// equal to it.
func (g *Group) Random(r *Int) *Int {
	r = r.Add(g.seed, g.rng.Rand(g.random))
	r = r.Mod(r, g.psub2)
	r = r.Add(r, g.two)
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
	g.Inverse(y, z)
	g.Exp(x, z, z)

	return z
}

//nilGroup returns a nil group
func nilGroup() *Group {
	return nil
}
