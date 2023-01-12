package broadcast

import (
	"gitlab.com/elixxir/crypto/rsa"
)

const (
	minKeySize = 1024 / 8
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

	// ensure the calculated key size is dividable by 128 to account
	// for issues in javascript
	selectedKeySize = (maxKeySize / 128) * 128
	selectedN = 1
	return
}

func calculateRsaToPublicPacketSize(keySize, numSubPayloads int) int {
	return keySize*numSubPayloads + rsa.GetScheme().GetMarshalWireLength(keySize)
}

func calculateRsaToPrivatePacketSize(keySize, numSubPayloads int) int {
	return keySize * numSubPayloads
}
