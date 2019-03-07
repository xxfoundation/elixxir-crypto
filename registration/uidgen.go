package registration

import (
	"errors"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/elixxir/primitives/id"
)

func GenUserID(pubKey *cyclic.Int, salt []byte) (*id.User, error) {
	if pubKey == nil || salt == nil {
		return nil, errors.New("PubKey and/or Salt are nil")
	}
	pubBytes := pubKey.Bytes()
	if len(pubBytes) == 0 || len(salt) == 0 {
		return nil, errors.New("PubKey and/or Salt are empty")
	}
	h, _ := hash.NewCMixHash()
	h.Write(pubBytes)
	h.Write(salt)
	userID := new(id.User).SetBytes(h.Sum(nil))
	return userID, nil
}
