package broadcast

import (
	"encoding/binary"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/rsa"
	"hash"
	"time"
)

// HashSecret secret is hashed first so that
// we can share all the inputs to the
// hkdf without giving out the secret.
func HashSecret(secret []byte) []byte {
	h, _ := channelHash(nil)
	h.Write(secret)
	return h.Sum(nil)
}

// HashPubKey is used to compute the hash of the RSA Public Key
func HashPubKey(pub rsa.PublicKey) []byte {
	h, _ := channelHash(nil)
	h.Write(pub.GetN().Bytes())
	eBytes := make([]byte, rsa.ELength)
	binary.BigEndian.PutUint32(eBytes, uint32(pub.GetE()))
	h.Write(eBytes)
	return h.Sum(nil)
}

// deriveIntermediary returns the BLAKE2b hash of the given arguments:
//
//	H(name | description | level | options | created | rsaPubHash | hashedSecret | salt)
func deriveIntermediary(name, description string, level PrivacyLevel,
	creation time.Time, opts options, salt, rsaPubHash, hashedSecret []byte) []byte {
	h, err := channelHash(nil)
	if err != nil {
		jww.FATAL.Panic(err)
	}

	write(h, []byte(name))
	write(h, []byte(description))
	write(h, []byte{byte(level)})
	write(h, opts.encode())
	write(h, marshalTime(creation))
	write(h, rsaPubHash)
	write(h, hashedSecret)
	write(h, salt)
	return h.Sum(nil)
}

// write moves the error handling into a single function to increase test
// coverage.
func write(h hash.Hash, data []byte) {
	_, err := h.Write(data)
	if err != nil {
		jww.FATAL.Panic(err)
	}
}

// marshalTime converts the time to unix nano bytes.
func marshalTime(t time.Time) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(t.UnixNano()))
	return b
}
