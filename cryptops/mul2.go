package cryptops

import "gitlab.com/elixxir/crypto/cyclic"

type Mul2Prototype func(g *cyclic.Group, ecr, key *cyclic.Int) *cyclic.Int

var Mul2 Mul2Prototype = func(g *cyclic.Group, ecr, key *cyclic.Int) *cyclic.Int{
	g.Mul(ecr,key,ecr)
	return ecr
}

//Returns the name for debugging
func (Mul2Prototype) GetName() string {
	return "Mul2"
}

//Returns the input size, used in safety checks
func (Mul2Prototype) GetInputSize() uint32 {
	return 1
}