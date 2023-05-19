package notifications

import (
	"crypto"
	"encoding/binary"
	"gitlab.com/elixxir/crypto/rsa"
	"golang.org/x/crypto/blake2b"
	"io"
	"time"
)

// SignIdentity is the client side signing code for a client registering an
// identity with the notifications server. It signs the identity the client's
// private key, along with the timestamp of signing (which the remote will
// verify is within +/- 5s, and a tag of the specific operation (registering
// or unregistering)
func SignIdentity(priv rsa.PrivateKey, identity [][]byte, timestamp time.Time,
	tag NotificationTag, rand io.Reader) ([]byte, error) {
	hashed := hashIdentity(identity, timestamp, tag)
	return priv.SignPSS(rand, crypto.SHA256, hashed, nil)
}

// VerifyIdentity is the server side verifying code for a client trying to
// register an identity with the notifications server. It verifies the identity
// with the clients verified public key, along with the
// timestamp of signing (which the remote will verify is withing +/- 5s,
// and a tag of the specific operation (registering or unregistering).
// WARNING: The tag must be provided locally, do not receive it over
// the wire
func VerifyIdentity(pub rsa.PublicKey, identity [][]byte, timestamp time.Time,
	tag NotificationTag, sig []byte) error {
	hashed := hashIdentity(identity, timestamp, tag)
	return pub.VerifyPSS(crypto.SHA256, hashed, sig, nil)
}

func hashIdentity(identity [][]byte, timestamp time.Time, tag NotificationTag) []byte {
	h, _ := blake2b.New256(nil)
	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(timestamp.UnixNano()))

	for i := range identity {
		h.Write(identity[i])
	}
	h.Write(timeBytes)
	h.Write([]byte{byte(tag)})
	return h.Sum(nil)
}
