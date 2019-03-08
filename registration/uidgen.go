package registration

import (
	"gitlab.com/elixxir/crypto/signature"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/elixxir/primitives/id"
	jww "github.com/spf13/jwalterweatherman"
)

func GenUserID(pubKey *signature.DSAPublicKey, salt []byte) *id.User {
	if pubKey == nil || salt == nil {
		jww.ERROR.Panicf("PubKey and/or Salt are nil")
	}
	pubBytes := pubKey.GetKey().Bytes()
	if len(pubBytes) == 0 || len(salt) == 0 {
		jww.ERROR.Panicf("PubKey and/or Salt are empty")
	}
	h, _ := hash.NewCMixHash()
	h.Write(pubBytes)
	h.Write(salt)
	userID := new(id.User).SetBytes(h.Sum(nil))
	return userID
}
