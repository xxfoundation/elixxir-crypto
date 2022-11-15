////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package authorize

import (
	"gitlab.com/xx_network/crypto/signature/rsa"
	"io"
)

// SignGatewayCert signs a given gateway TLS certificate with the passed in private key
func SignGatewayCert(rng io.Reader, gwRsa *rsa.PrivateKey, cert []byte) ([]byte, error) {
	return rsa.Sign(rng, gwRsa, hashType, hashGatewayCert(cert), rsa.NewDefaultOptions())
}

// VerifyGatewayCert verifies the signature on a passed in TLS certificate
func VerifyGatewayCert(gwPub *rsa.PublicKey, sig, cert []byte) error {
	return rsa.Verify(gwPub, hashType, hashGatewayCert(cert), sig, rsa.NewDefaultOptions())
}

func hashGatewayCert(cert []byte) []byte {
	h := hashType.New()
	h.Write(cert)
	return h.Sum(nil)
}
