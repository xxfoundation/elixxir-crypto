package broadcast

import (
	"encoding/json"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/e2e/auth"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"gitlab.com/xx_network/primitives/id"
	"golang.org/x/crypto/chacha20"
)

// Error messages.
const (
	// Symmetric.Decrypt
	errVerifyMAC = "failed to verify MAC"

	// NewSymmetricKey
	errMakeSymmetricKeyHash = "[BCAST] Failed to create new hash for " +
		"symmetric broadcast channel key: %+v"
)

const symmetricKeyConst = "symmetricBroadcastChannelKey"

// Symmetric uniquely identifies a symmetric broadcast channel.
type Symmetric struct {
	ReceptionID *id.ID // ReceptionID = H(Name, Description, Salt, RsaPubKey)
	Name        string
	Description string
	Salt        []byte
	RsaPubKey   *rsa.PublicKey

	// Only appears in memory, is not contained in the marshalled version.
	// Lazily evaluated on first use.
	// key = H(ReceptionID)
	key []byte
}

// Encrypt encrypts the given payload and returns it with a MAC and fingerprint.
func (s *Symmetric) Encrypt(payload []byte, csprng csprng.Source) (
	encryptedPayload, mac []byte, nonce format.Fingerprint) {
	nonce = newNonce(csprng)
	if s.key == nil {
		s.key = NewSymmetricKey(s.ReceptionID)
	}

	key := newMessageKey(nonce, s.key)
	encryptedPayload = auth.Crypt(key, nonce[:chacha20.NonceSizeX], payload)
	mac = makeMAC(key, encryptedPayload)

	return encryptedPayload, mac, nonce
}

// Decrypt decrypts the given encrypted payload and returns it. Returns an error
// if the MAC cannot be verified.
func (s *Symmetric) Decrypt(
	encryptedPayload, mac []byte, nonce format.Fingerprint) ([]byte, error) {
	if s.key == nil {
		s.key = NewSymmetricKey(s.ReceptionID)
	}

	key := newMessageKey(nonce, s.key)
	payload := auth.Crypt(key, nonce[:chacha20.NonceSizeX], encryptedPayload)

	if !verifyMAC(key, encryptedPayload, mac) {
		return nil, errors.New(errVerifyMAC)
	}

	return payload, nil
}

// Marshal serialises the Symmetric object into JSON.
func (s *Symmetric) Marshal() ([]byte, error) {
	return json.Marshal(s)
}

// UnmarshalSymmetric deserializes the JSON into a new Symmetric.
func UnmarshalSymmetric(data []byte) (*Symmetric, error) {
	var s Symmetric
	return &s, json.Unmarshal(data, &s)
}

// NewSymmetricKey generates a new symmetric channel key from its reception ID.
func NewSymmetricKey(receptionID *id.ID) []byte {
	// Create new hash
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.FATAL.Panicf(errMakeSymmetricKeyHash, err)
	}

	h.Write(receptionID.Bytes())
	h.Write([]byte(symmetricKeyConst))

	return h.Sum(nil)
}

// NewSymmetricID creates a new symmetric channel ID based on name, description, salt and RSA public key
func NewSymmetricID(name, description string, salt, rsaPub []byte) (*id.ID, error) {
	h, err := hash.NewCMixHash()
	if err != nil {
		return nil, err
	}
	_, err = h.Write([]byte(name))
	if err != nil {
		return nil, err
	}
	_, err = h.Write([]byte(description))
	if err != nil {
		return nil, err
	}
	_, err = h.Write(salt)
	if err != nil {
		return nil, err
	}
	_, err = h.Write(rsaPub)
	if err != nil {
		return nil, err
	}

	sid := &id.ID{}
	copy(sid[:], h.Sum(nil))
	sid.SetType(id.User)
	return sid, nil
}
