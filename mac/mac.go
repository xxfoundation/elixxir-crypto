package mac


import (
	"gitlab.com/privategrity/crypto/hash"
)

// Message Authentication Code - Appends key to end of messge, runs our
// global hash on it, and returns the MAC -- in other words:
// MAC(M, K) = Hash(M + K)
func MessageAuthenticationCode(message, key []byte) []byte {
	h = NewCMixHash()
	h.Write(message)
	h.Write(key)
	return h.Sum(nil)
}

// Verify a message authentication code, return true if it works, or
// false if it doesn't
func VerifyMessageAuthenticationCode(message, key, mac []byte) (bool) {
	vMac = MessageAuthenticationCode(message, key)
	if len(vMac) != len(mac) {
		return false
	}
	for i := 0; i < len(vMac); i++ {
		if vMac[i] != mac[i] {
			return false
		}
	}
	return true
}
