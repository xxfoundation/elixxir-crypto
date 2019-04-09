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

// Wraps existing keygen operations in the messaging package
type keygenPrototype func(grp *cyclic.Group, salt []byte,
	baseKey *cyclic.Int) (key *cyclic.Int)

type EncryptionKeygenPrototype keygenPrototype
type DecryptionKeygenPrototype keygenPrototype

// Define the actual cryptops
var EncryptionKeygen EncryptionKeygenPrototype = func(group *cyclic.Group,
	salt []byte, baseKey *cyclic.Int) (key *cyclic.Int) {
	return cmix.NewEncryptionKey(salt, baseKey, group)
}

func (EncryptionKeygenPrototype) GetName() string {
	return "EncryptionKeygen"
}

func (EncryptionKeygenPrototype) GetInputSize() uint32 {
	return 1
}

var DecryptionKeygen DecryptionKeygenPrototype = func(group *cyclic.Group,
	salt []byte, baseKey *cyclic.Int) (key *cyclic.Int) {
	return cmix.NewDecryptionKey(salt, baseKey, group)
}

func (DecryptionKeygenPrototype) GetName() string {
	return "DecryptionKeygen"
}

func (DecryptionKeygenPrototype) GetInputSize() uint32 {
	return 1
}
