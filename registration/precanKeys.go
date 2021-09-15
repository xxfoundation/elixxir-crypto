////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package registration

import jww "github.com/spf13/jwalterweatherman"

// This file contains a hardcoded TLS keypair and logic to access these keys.
// This is used for registration of a precanned client with a cMix node.
// These keys are intended for development use only, NOT FOR PRODUCTION.

// precanCert is a hardcoded certificate. Associated with the precanKey as part
// of the precanned TLS keypair. Expires September 15, 2023.
const precanCert = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
`

// precanKey is a hardcoded RSA private key. Associated with the precanCert
// as part of the precanned TLS keypair.
const precanKey = `-----BEGIN PRIVATE KEY-----
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
LCbUKa+djoH8nrdugeR9QXQcVPBvvhI=
-----END PRIVATE KEY-----
`

// GetPrecannedKey retrieves the precanned RSA key. This should only be used
// for development purposes.
func GetPrecannedKey() string {
	jww.ERROR.Printf("USE OF PRECANNED KEY IS NOT SECURE AND SHOULD " +
		"ONLY BE USED FOR DEVELOPMENT PURPOSES!")
	return precanKey
}

// GetPrecannedCert retrieves the precanned TLS certificate. This should only
// be used for development purposes.
func GetPrecannedCert() string {
	jww.ERROR.Printf("USE OF PRECANNED CERTIFICATE IS NOT SECURE AND SHOULD " +
		"ONLY BE USED FOR DEVELOPMENT PURPOSES!")
	return precanCert
}

// GetPrecannedKeyPair retrieves the precanned TLS keypair. This should only
// be used for development purposes.
func GetPrecannedKeyPair() (cert, key string) {
	jww.ERROR.Printf("USE OF PRECANNED TLS KEYPAIR IS NOT SECURE AND SHOULD " +
		"ONLY BE USED FOR DEVELOPMENT PURPOSES!")
	return precanCert, precanKey
}
