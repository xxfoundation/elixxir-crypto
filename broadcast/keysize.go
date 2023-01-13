package broadcast

import (
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/rsa"
)

// calculateKeySize finds the optimal key size and number of sub-packets smaller
// than the key size and larger than the minKeySize. Both payloadSize and
// maxKeySizeGoal should be in bytes.
func calculateKeySize(payloadSize int) (selectedKeySize int, selectedN int) {

	// Some payload is taken up by data for the sized broadcast included in the
	// outer symmetric encryption layer; account for that.
	sizedPayloadSize := MaxSizedBroadcastPayloadSize(payloadSize)

	// Calculate the maximum key size that can be used for a given payload
	maxKeySize := (sizedPayloadSize - rsa.ELength) / 2

	// handle the case where the calculated key size is negative.
	// this should be completely impossible
	if maxKeySize < 0 {
		jww.FATAL.Printf("Calculated key size (%d) is negative,"+
			"his is invalid and should be impossible", maxKeySize)
	}

	// truncate to ensure the calculated key size is a factor by 128
	// to account for issues in javascript subtle crypto implementation
	// of RSA
	// this code takes advantage of the fact that division in integer
	// space clamps down. As a result, this ensures the key size that the
	// first factor of 128 in bytes, which is 16 below (or equal to) maxKeySize
	selectedKeySize = (maxKeySize / 16) * 16

	// there are 2 sub payloads, but 1 will be used for the public key,
	// so the number of usable sub payloads is 1
	selectedN = 1
	return
}

func calculateRsaToPublicPacketSize(keySize, numSubPayloads int) int {
	return keySize*numSubPayloads + rsa.GetScheme().GetMarshalWireLength(keySize)
}

func calculateRsaToPrivatePacketSize(keySize, numSubPayloads int) int {
	return keySize * numSubPayloads
}
