////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package cryptops

type Cryptop interface {
	//Returns the name.  Used for debugging.
	GetName() string
	//Gets the number of parallel computations the cryptop does at once.
	//A value of zero denotes it is arbitrary
	GetInputSize() uint32
}
