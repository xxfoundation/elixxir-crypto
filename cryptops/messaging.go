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

func (DecryptionKeygenPrototype) GetName() string{
	return "DecryptionKeygen"
}

func (EncryptionKeygenPrototype) GetName() string{
	return "EncryptionKeygen"
}

func (DecryptionKeygenPrototype) GetInputSize() uint32 {
	return 1
}

func (EncryptionKeygenPrototype) GetInputSize() uint32 {
	return 1
}

// Define the actual cryptops
var EncryptionKeygen EncryptionKeygenPrototype = func(group *cyclic.Group,
	salt []byte, baseKey *cyclic.Int) (key *cyclic.Int) {
		return cmix.NewEncryptionKey(salt, baseKey, group)
}

var DecryptionKeygen DecryptionKeygenPrototype = func(group *cyclic.Group,
	salt []byte, baseKey *cyclic.Int) (key *cyclic.Int) {
		return cmix.NewDecryptionKey(salt, baseKey, group)
}
