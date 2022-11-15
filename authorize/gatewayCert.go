////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

// Package gatewayHttps contains logic for signing and verifying info used for
// serving via HTTPS on gateways - explicitly, for ACME tokens and the
// well-formed certificates
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
