////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

// Package cryptops wraps various cryptographic operations around a generic interface.
// Operations include but are not limited to: key generation, ElGamal, multiplication, etc.
package cryptops

type Cryptop interface {
	//Returns the name.  Used for debugging.
	GetName() string
	//Gets the number of parallel computations the cryptop does at once.
	//A value of zero denotes it is arbitrary
	GetInputSize() uint32
}
