package cryptops

import "gitlab.com/elixxir/crypto/cyclic"

type ElGamalPrototype func(g *cyclic.Group, key, privatekey, publicCypherKey, ecrKeys, cypher *cyclic.Int)

//Implements the modified version of ElGamal within the cryptops interface.
//Modifies ecrkeys and cypher to make its output.
//ecrkeys = ecrkeys*key*(g^privatekey)%p
//cypher  = cypher*(publicCypherKey^privatekey)%p
//More details can be found in the appendix of https://drive.google.com/open?id=1ha8QtUI9Tk_sCIKWN-QE8YHZ7AKofKrV
//At Engineering/Technical Docs/CMIX.pdf
var ElGamal ElGamalPrototype = func(g *cyclic.Group, key, privateKey, publicCypherKey, ecrKeys, cypher *cyclic.Int) {
	tmp := g.NewMaxInt()

	//ecrkeys = ecrkeys*key*(g^privatekey)%p
	g.ExpG(privateKey, tmp)
	g.Mul(key, tmp, tmp)
	g.Mul(tmp, ecrKeys, ecrKeys)

	//cypher  = cypher*(publicCypherKey^privatekey)%p
	g.Exp(publicCypherKey, privateKey, tmp)
	g.Mul(tmp, cypher, cypher)
}

func (ElGamalPrototype) GetName() string {
	return "ElGamal"
}

func (ElGamalPrototype) GetInputSize() uint32 {
	return 1
}
