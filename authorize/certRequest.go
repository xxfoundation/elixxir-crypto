////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package authorize

import (
	"encoding/binary"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"io"
	"time"
)

var hashType = hash.CMixHash

// SignCertRequest signs the ACME token & other info sent with an AuthorizerCertRequest
func SignCertRequest(rng io.Reader, gwRsa *rsa.PrivateKey,
	acmeToken string, now time.Time) ([]byte, error) {
	hashed, err := hashCertRequestInfo(acmeToken, now)
	if err != nil {
		return nil, err
	}
	return rsa.Sign(rng, gwRsa, hashType, hashed, rsa.NewDefaultOptions())
}

// VerifyCertRequest verifies the signature on an ACME token & other info sent with an AuthorizerCertRequest
func VerifyCertRequest(gwPub *rsa.PublicKey, sig []byte,
	acmeToken string, now, signedTS time.Time, delta time.Duration) error {
	err := checkTimeBound(now, signedTS, delta)
	if err != nil {
		return err
	}
	hashed, err := hashCertRequestInfo(acmeToken, signedTS)
	if err != nil {
		return err
	}
	return rsa.Verify(gwPub, hashType, hashed, sig, rsa.NewDefaultOptions())
}

func hashCertRequestInfo(acmeToken string, timestamp time.Time) ([]byte, error) {
	h := hashType.New()
	h.Write([]byte(acmeToken))
	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(timestamp.UnixNano()))
	h.Write(tsBytes)
	return h.Sum(nil), nil
}
