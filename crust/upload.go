package crust

import (
	"encoding/binary"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"hash"
	"io"
	"time"
)

// todo: docstring
func SignUpload(rand io.Reader, userPrivKey *rsa.PrivateKey,
	fileHash, timestamp []byte) ([]byte, error) {
	opts := rsa.NewDefaultOptions()
	hashed := makeUploadHash(fileHash, timestamp,
		opts.Hash.New())

	return rsa.Sign(rand, userPrivKey, opts.Hash, hashed, opts)
}

// todo: docstring
func VerifyUpload(userPublicKey *rsa.PublicKey,
	fileHash, timestamp, signature []byte) error {
	opts := rsa.NewDefaultOptions()
	hashed := makeUploadHash(fileHash, timestamp,
		opts.Hash.New())

	return rsa.Verify(userPublicKey, opts.Hash, hashed, signature, opts)
}

// todo: docstring
func SerializeTimestamp(timestamp time.Time) []byte {
	tsUnix := timestamp.UnixNano()
	tsSerialize := make([]byte, 8)
	binary.BigEndian.PutUint64(tsSerialize, uint64(tsUnix))
	return tsSerialize
}

// todo: docstring
func makeUploadHash(fileHash []byte, ts []byte, h hash.Hash) []byte {
	h.Write(fileHash)
	h.Write(ts)
	return h.Sum(nil)
}
