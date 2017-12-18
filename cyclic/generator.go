package cyclic

import "crypto/rand"

func NewGen(max *Int) Gen {
	gen := Gen{max}
	return gen
}

func (gen Gen) Rand(x *Int) *Int {
	ran, err := rand.Int(rand.Reader, gen.max.value)
	if err != nil {
		return nil
	}
	x.value = ran
	if x.IsInt64() {
		xint := x.Int64()
		if xint < 2 {
			x = NewInt(2)
		}
	}
	return x
}
