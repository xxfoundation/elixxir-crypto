package dm

import (
	"crypto/ed25519"
	"encoding/base64"
	"gitlab.com/elixxir/crypto/nike/ecdh"
	"gitlab.com/xx_network/primitives/id"
	"golang.org/x/crypto/blake2b"
)

const sihTagSalt = "sihTagSalt"

// MakeSihTag returns a tag for a recipient and a sender under a DH construction
// so that only they can generate it
func MakeSihTag(them ed25519.PublicKey, me ed25519.PrivateKey,
	recipientID *id.ID) string {
	themECDH := ecdh.Edwards2EcdhNikePublicKey(them)
	meECDH := ecdh.Edwards2EcdhNikePrivateKey(me)

	dhKey := meECDH.DeriveSecret(themECDH)

	h, _ := blake2b.New256(nil)
	h.Write(dhKey)
	h.Write(recipientID.Bytes())
	h.Write([]byte(sihTagSalt))

	tag := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(tag)
}
