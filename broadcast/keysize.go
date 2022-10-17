package broadcast

import (
	"gitlab.com/elixxir/crypto/rsa"
	"math"
)

const (
	minKeysize = 1024/8
)

// calculateKeySize finds the optimal key size and number of subpackets smaller
// than the keysize and larger than the minkeysize.
// both paylaodSize and maxKeysize should be in bytes
func calculateKeySize(payloadSize, maxKeySizeGoal int)(selectedKeySize int, selectedN int){

	// some of the payload is taken up by data for the sized broadcast included
	// in the outer symmetric encryption layer. account for that.
	sizedPayloadSize := MaxSizedBroadcastPayloadSize(payloadSize)

	// calculate the maximum keysize that can be used for a given payload
	maxkey := (sizedPayloadSize-rsa.ELength)/2

	// if the requested key size is greater than the maximum, reduce it to the
	// maximum
	if maxKeySizeGoal>maxkey{
		selectedKeySize = maxkey
		selectedN = 1
		return
	}

	// otherwise, find the closes key size to the requested which fits.
	// it will likely be smaller because an integer number of payloads for the
	// key size need to fit in the payload. The n needs to be "ceilinged"
	// in order to ensure the given keysize goal is treated as an upper bound
	selectedN = int(math.Ceil(float64(sizedPayloadSize-rsa.ELength)/
		float64(maxKeySizeGoal)-1))

	// Run the above calculation in reverse in order to get from the floored n
	// the appropriate key size back
	selectedKeySize = (sizedPayloadSize-rsa.ELength)/(selectedN+1)

	return
}

func calculateRsaToPublicPacketSize(keysize, numSubPayloads int)int {
	return keysize*numSubPayloads + rsa.GetScheme().GetMarshalWireLength(keysize)
}

func calculateRsaToPrivatePacketSize(keysize, numSubPayloads int)int {
	return keysize*numSubPayloads
}
