package e2e

import (
	"fmt"
	jww "github.com/spf13/jwalterweatherman"
	"git.xx.network/elixxir/crypto/cyclic"
	"git.xx.network/elixxir/crypto/hash"
	"git.xx.network/xx_network/primitives/id"
)

// creates a unique relationship fingerprint which can be used to ensure keys
// are unique and that message IDs are unique
func MakeRelationshipFingerprint(pubkeyA, pubkeyB *cyclic.Int, sender,
	receiver *id.ID) []byte {
	h, err := hash.NewCMixHash()
	if err != nil {
		panic(fmt.Sprintf("Failed to get hash to make relationship"+
			" fingerprint with: %s", err))
	}

	switch pubkeyA.Cmp(pubkeyB) {
	case 1:
		h.Write(pubkeyA.Bytes())
		h.Write(pubkeyB.Bytes())
	default:
		jww.WARN.Printf("Public keys the same, relationship " +
			"fingerproint uniqueness not assured")
		fallthrough
	case -1:
		h.Write(pubkeyB.Bytes())
		h.Write(pubkeyA.Bytes())
	}

	h.Write(sender.Bytes())
	h.Write(receiver.Bytes())
	return h.Sum(nil)
}
