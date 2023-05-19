package notifications

import (
	"crypto/rand"
	"gitlab.com/elixxir/crypto/rsa"
	"testing"
	"time"
)

func TestSignVerifyIdentity(t *testing.T) {
	sLocal := rsa.GetScheme()
	rng := rand.Reader

	privKey, err := sLocal.GenerateDefault(rng)
	if err != nil {
		t.Errorf("GenerateDefault: %v", err)
	}

	privKey2, err := sLocal.GenerateDefault(rng)
	if err != nil {
		t.Errorf("GenerateDefault: %v", err)
	}

	identity := [][]byte{[]byte("testIdentity"), []byte("testIdentity2")}
	ts := time.Now()
	tag := RegisterTrackedIDTag

	sig, err := SignIdentity(privKey, identity, ts, tag, rng)
	if err != nil {
		t.Fatalf("Failed to sign: %+v", err)
	}

	// should succeed
	err = VerifyIdentity(privKey.Public(), identity, ts, tag, sig)
	if err != nil {
		t.Errorf("Failed to verify: %+v", err)
	}

	// bad pubkey
	err = VerifyIdentity(privKey2.Public(), identity, ts, tag, sig)
	if err == nil {
		t.Errorf("Verified when it shouldnt: %+v", err)
	}

	// bad Identity
	err = VerifyIdentity(privKey.Public(), [][]byte{[]byte("bad")}, ts, tag, sig)
	if err == nil {
		t.Errorf("Verified when it shouldnt: %+v", err)
	}

	// bad ts
	err = VerifyIdentity(privKey.Public(), identity, ts.Add(10*time.Hour), tag, sig)
	if err == nil {
		t.Errorf("Verified when it shouldnt: %+v", err)
	}

	// bad tag
	err = VerifyIdentity(privKey.Public(), identity, ts, UnregisterTokenTag, sig)
	if err == nil {
		t.Errorf("Verified when it shouldnt: %+v", err)
	}

	// bad sig
	sig[0] = 0
	err = VerifyIdentity(privKey.Public(), identity, ts, tag, sig)
	if err == nil {
		t.Errorf("Verified when it shouldnt: %+v", err)
	}
}
