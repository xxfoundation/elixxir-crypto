////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package cryptops

import (
	"gitlab.com/elixxir/crypto/cmix"
	"gitlab.com/elixxir/crypto/cyclic"
)

// Wraps existing keygen operations in the cmix package
type KeygenPrototype func(group *cyclic.Group,
	salt []byte, baseKey, generatedKey *cyclic.Int)

var Keygen KeygenPrototype = cmix.NodeKeyGen

func (KeygenPrototype) GetName() string {
	return "Keygen"
}

func (KeygenPrototype) GetInputSize() uint32 {
	return 1
}
