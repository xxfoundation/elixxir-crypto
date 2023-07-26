package notifications

import (
	"crypto/rand"
	"gitlab.com/elixxir/crypto/rsa"
	"testing"
	"time"
)

func TestSignVerifyToken(t *testing.T) {
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

	token := "aaaa"
	app := "test"
	ts := time.Now()
	tag := RegisterTokenTag

	sig, err := SignToken(privKey, token, app, ts, tag, rng)
	if err != nil {
		t.Fatalf("Failed to sign: %+v", err)
	}

	// should succeed
	err = VerifyToken(privKey.Public(), token, app, ts, tag, sig)
	if err != nil {
		t.Errorf("Failed to verify: %+v", err)
	}

	// bad pubkey
	err = VerifyToken(privKey2.Public(), token, app, ts, tag, sig)
	if err == nil {
		t.Errorf("Verified when it shouldnt: %+v", err)
	}

	// bad token
	err = VerifyToken(privKey.Public(), "bad", app, ts, tag, sig)
	if err == nil {
		t.Errorf("Verified when it shouldnt: %+v", err)
	}

	// bad app
	err = VerifyToken(privKey.Public(), token, "bad", ts, tag, sig)
	if err == nil {
		t.Errorf("Verified when it shouldnt: %+v", err)
	}

	// bad ts
	err = VerifyToken(privKey.Public(), token, app, ts.Add(10*time.Hour), tag, sig)
	if err == nil {
		t.Errorf("Verified when it shouldnt: %+v", err)
	}

	// bad tag
	err = VerifyToken(privKey.Public(), token, app, ts, UnregisterTokenTag, sig)
	if err == nil {
		t.Errorf("Verified when it shouldnt: %+v", err)
	}

	// bad sig
	sig[0] = 0
	err = VerifyToken(privKey.Public(), token, app, ts, tag, sig)
	if err == nil {
		t.Errorf("Verified when it shouldnt: %+v", err)
	}
}
