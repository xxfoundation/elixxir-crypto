////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package crust

import (
	"github.com/pkg/errors"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"time"
)

// JointVerify verifies both the upload and the verification signature at once
// Both will be sent as part of the auth headers to Crust's upload and pinning
// service, this will make proper usage more clear
// Returns nil for the error if the verification is successful
func JointVerify(UDPubkey, userPublicKey *rsa.PublicKey, usernameHash,
	fileHash, verificationSignature, uploadSignature []byte, uploadTs,
	now time.Time) error {

	if err := VerifyVerificationSignature(UDPubkey, usernameHash,
		userPublicKey, verificationSignature); err != nil {
		return errors.WithMessage(err,
			"Failed to verify the Verification Signature")
	}

	if err := VerifyUpload(userPublicKey, now, uploadTs, fileHash,
		uploadSignature); err != nil {
		return errors.WithMessage(err,
			"Failed to verify the Upload Signature")
	}

	return nil
}
