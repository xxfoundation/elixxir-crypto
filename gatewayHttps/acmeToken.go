////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package gatewayHttps

import (
	"encoding/binary"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"io"
)

var hashType = hash.CMixHash

// SignAcmeToken signs the ACME token & other info sent with an AuthorizerCertRequest
func SignAcmeToken(rng io.Reader, gwRsa *rsa.PrivateKey, ipAddress,
	acmeToken string, timestamp uint64) ([]byte, error) {
	hashed := hashAcmeInfo(ipAddress, acmeToken, timestamp)
	return rsa.Sign(rng, gwRsa, hashType, hashed, rsa.NewDefaultOptions())
}

// VerifyAcmeToken verifies the signature on an ACME token & other info sent with an AuthorizerCertRequest
func VerifyAcmeToken(gwPub *rsa.PublicKey, sig []byte, ipAddress,
	acmeToken string, timestamp uint64) error {
	hashed := hashAcmeInfo(ipAddress, acmeToken, timestamp)
	return rsa.Verify(gwPub, hashType, hashed, sig, rsa.NewDefaultOptions())
}

func hashAcmeInfo(ipAddress, acmeToken string, timestamp uint64) []byte {
	h := hashType.New()
	h.Write([]byte(ipAddress))
	h.Write([]byte(acmeToken))
	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, timestamp)
	h.Write(tsBytes)
	return h.Sum(nil)
}
