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
type KeygenPrototype func(grp *cyclic.Group, salt []byte,
	baseKey *cyclic.Int) (key *cyclic.Int)

var Keygen KeygenPrototype = func(group *cyclic.Group,
	salt []byte, baseKey *cyclic.Int) (key *cyclic.Int) {
	output := group.NewInt(1)
	cmix.NodeKeyGen(group, salt, baseKey, output)
	return output
}

func (KeygenPrototype) GetName() string {
	return "Keygen"
}

func (KeygenPrototype) GetInputSize() uint32 {
	return 1
}
