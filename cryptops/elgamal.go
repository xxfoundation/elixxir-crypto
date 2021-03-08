////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// Package cryptops wraps various cryptographic operations around a generic interface.
// Operations include but are not limited to: key generation, ElGamal, multiplication, etc.
package cryptops

import "gitlab.com/elixxir/crypto/cyclic"

type ElGamalPrototype func(g *cyclic.Group, key, privatekey, publicCypherKey, ecrKeys, cypher *cyclic.Int)

// ElGamal implements the modified version of ElGamal within the cryptops interface.
//  Modifies ecrkeys and cypher to make its output.
//  ecrkeys = ecrkeys*key*(g^privateKey)%p
//  cypher  = cypher*(publicCypherKey^privateKey)%p
//  More details can be found in the appendix of https://drive.google.com/open?id=1ha8QtUI9Tk_sCIKWN-QE8YHZ7AKofKrV
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

// GetName returns the name for debugging
func (ElGamalPrototype) GetName() string {
	return "ElGamal"
}

// GetInputSize returns the input size, used in safety checks
func (ElGamalPrototype) GetInputSize() uint32 {
	return 1
}
