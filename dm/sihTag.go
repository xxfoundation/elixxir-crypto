package dm

import (
	"crypto/ed25519"
	"encoding/base64"
	"gitlab.com/elixxir/crypto/nike/ecdh"
	"golang.org/x/crypto/blake2b"
)

const sihTagSalt = "sihTagSalt"

// MakeSenderSihTag creates an SIH tag for a sent DM message.
func MakeSenderSihTag(themPub ed25519.PublicKey, mePriv ed25519.PrivateKey) string {
	return makeSihTag(themPub, mePriv, themPub)
}

// MakeReceiverSihTag creates an SIH tag for a received DM message.
func MakeReceiverSihTag(themPub ed25519.PublicKey, mePriv ed25519.PrivateKey) string {
	mePub := mePriv.Public()
	return makeSihTag(themPub, mePriv, mePub.(ed25519.PublicKey))
}

// makeSihTag returns a tag for a recipient and a sender under a DH construction
// so that only they can generate it.
func makeSihTag(dhPub ed25519.PublicKey, dhPriv ed25519.PrivateKey,
	receiverPub ed25519.PublicKey) string {
	themECDH := ecdh.Edwards2EcdhNikePublicKey(dhPub)
	meECDH := ecdh.Edwards2EcdhNikePrivateKey(dhPriv)

	dhKey := meECDH.DeriveSecret(themECDH)

	h, _ := blake2b.New256(nil)
	h.Write(dhKey)
	h.Write(receiverPub)
	h.Write([]byte(sihTagSalt))

	tag := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(tag)
}
