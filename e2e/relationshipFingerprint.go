package e2e

import (
	"fmt"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/xx_network/primitives/id"
)

// creates a unique relationship fingerprint which can be used to ensure keys
// are unique and that message IDs are unique
func MakeRelationshipFingerprint(originKey *cyclic.Int, sender,
	receiver *id.ID) []byte {
	h, err := hash.NewCMixHash()
	if err != nil {
		panic(fmt.Sprintf("Failed to get hash to make relationship"+
			" fingerprint with: %s", err))
	}
	h.Write(originKey.Bytes())
	h.Write(sender.Bytes())
	h.Write(receiver.Bytes())
	return h.Sum(nil)
}
