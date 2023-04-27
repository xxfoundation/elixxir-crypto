package notifications

import (
	"encoding/binary"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/elixxir/crypto/rsa"
	"golang.org/x/crypto/blake2b"
	"io"
	"time"
)

// SignToken is the client side signing code for a client registering a token
// with the notifications server. It signs the token and app designator with
// the client's private key, along with the timestamp of signing
// (which the remote will verify is within +/- 5s), and a tag of the specific
// operation (registering or unregistering)
func SignToken(priv rsa.PrivateKey, token, app string, timestamp time.Time,
	tag NotificationTag, rand io.Reader) ([]byte, error) {
	hashed := hashToken(token, app, timestamp, tag)
	return priv.SignPSS(rand, hash.CMixHash, hashed, nil)
}

// VerifyToken is the server side verifying code for a client trying to
// register a token with the notifications server. It verifies the token and
// app designator with the clients verified public key, along with the
// timestamp of signing (which the remote will verify is withing +/- 5s,
// and a tag of the specific operation (registering or unregistering).
// WARNING: The tag must be provided locally, do not receive it over
// the wire
func VerifyToken(pub rsa.PublicKey, token, app string, timestamp time.Time,
	tag NotificationTag, sig []byte) error {
	hashed := hashToken(token, app, timestamp, tag)
	return pub.VerifyPSS(hash.CMixHash, hashed, sig, nil)
}

func hashToken(token, app string, timestamp time.Time, tag NotificationTag) []byte {
	h, _ := blake2b.New256(nil)
	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(timestamp.UnixNano()))

	h.Write([]byte(token))
	h.Write([]byte(app))
	h.Write(timeBytes)
	h.Write([]byte{byte(tag)})
	return h.Sum(nil)
}
