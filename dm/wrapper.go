package dm

import "gitlab.com/yawning/nyquist.git/dh"

type PrivateKey struct {
	privateKey dh.Keypair
}

type PublicKey struct {
	publicKey dh.PublicKey
}
