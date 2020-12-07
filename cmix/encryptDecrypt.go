/* Copyright 2020 xx network SEZC

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.

*/

// Package cmix contains utility functions for preparing, encrypting, and decrypting
// messages sent and received by cMix. In cMix, messages are encrypted by the sending clients,
// partially decrypted by the nodes, then re-encrypted for the receiving clients by the nodes,
// and finally decrypted by the receiving clients. The operational encrypt/decrypt for each of
// these operations is the same. There is also a key selection system driven by a ratcheting protocol.

// Any extensions or modifications to the core messaging functionality should be done here,
// except for conversion of the encrypted message types to the comms messages used for transmitting data.
package cmix

import (
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/primitives/format"
	"golang.org/x/crypto/blake2b"
)

// ClientEncrypt encrypts the message for the client by multiplying the
// inverted encryption key by the message payload
func ClientEncrypt(grp *cyclic.Group, msg format.Message,
	salt []byte, baseKeys []*cyclic.Int) format.Message {

	// Get the salt for associated data
	hash, err := blake2b.New256(nil)
	if err != nil {
		panic("E2E Client Encrypt could not get blake2b Hash")
	}
	hash.Reset()
	hash.Write(salt)

	// Get encryption keys
	keyEcrA := ClientKeyGen(grp, salt, baseKeys)
	keyEcrB := ClientKeyGen(grp, hash.Sum(nil), baseKeys)

	// Get message payloads as cyclic integers
	payloadA := grp.NewIntFromBytes(msg.GetPayloadA())
	payloadB := grp.NewIntFromBytes(msg.GetPayloadB())

	// Encrypt payload A with the key
	EcrPayloadA := grp.Mul(keyEcrA, payloadA, grp.NewInt(1))
	EcrPayloadB := grp.Mul(keyEcrB, payloadB, grp.NewInt(1))

	primeLen := grp.GetP().ByteLen()

	// Create the encrypted message
	encryptedMsg := format.NewMessage(primeLen)

	encryptedMsg.SetPayloadA(EcrPayloadA.LeftpadBytes(uint64(primeLen)))
	encryptedMsg.SetPayloadB(EcrPayloadB.LeftpadBytes(uint64(primeLen)))

	return encryptedMsg

}
