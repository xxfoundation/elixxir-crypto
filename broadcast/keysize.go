package broadcast

import (
	"gitlab.com/elixxir/crypto/rsa"
	"math"
)

const (
	minKeySize = 1024 / 8
)

// calculateKeySize finds the optimal key size and number of sub-packets smaller
// than the key size and larger than the minKeySize. Both payloadSize and
// maxKeySizeGoal should be in bytes.
func calculateKeySize(
	payloadSize, maxKeySizeGoal int) (selectedKeySize int, selectedN int) {

	// Some payload is taken up by data for the sized broadcast included in the
	// outer symmetric encryption layer; account for that.
	sizedPayloadSize := MaxSizedBroadcastPayloadSize(payloadSize)

	// Calculate the maximum key size that can be used for a given payload
	maxKeySize := (sizedPayloadSize - rsa.ELength) / 2

	// If the requested key size is greater than the maximum, ten reduce it to
	// the maximum key size
	if maxKeySizeGoal > maxKeySize {
		selectedKeySize = maxKeySize
		selectedN = 1
		return
	}

	// Otherwise, find the closest key size to the requested that fits. It will
	// likely be smaller because an integer number of payloads for the key size
	// needs to fit in the payload. The n needs to be "ceilinged" to ensure the
	// given key size goal is treated as an upper bound.
	selectedN = int(math.Ceil(
		float64(sizedPayloadSize-rsa.ELength)/float64(maxKeySizeGoal) - 1))

	// Run the above calculation in reverse in order to get from the floored n
	// the appropriate key size back
	selectedKeySize = (sizedPayloadSize - rsa.ELength) / (selectedN + 1)

	// round down to the closest multiple of 8 (this is a requirement for
	// subtleCrypto compatibility)
	selectedKeySize = (selectedKeySize / 8) * 8

	return
}

func calculateRsaToPublicPacketSize(keySize, numSubPayloads int) int {
	return keySize*numSubPayloads + rsa.GetScheme().GetMarshalWireLength(keySize)
}

func calculateRsaToPrivatePacketSize(keySize, numSubPayloads int) int {
	return keySize * numSubPayloads
}
