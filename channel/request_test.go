package channel

import (
	"crypto/ed25519"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"testing"
	"time"
)

// Generates a set of RSA and Ed25519 keys and tests signing and verifying a
// Request using SignChannelIdentityRequest and VerifyChannelIdentityRequest.
func TestSignVerify(t *testing.T) {
	rng := csprng.NewSystemRNG()
	rsaPriv, err := rsa.GenerateKey(rng, rsa.DefaultRSABitLen)
	if err != nil {
		t.Fatalf("Failed to generate rsa private key: %+v", err)
	}

	edPub, _, err := ed25519.GenerateKey(rng)
	if err != nil {
		t.Fatalf("Failed to generate ed25519 key: %+v", err)
	}

	ts := time.Now()

	sig, err := SignChannelIdentityRequest(edPub, ts, rsaPriv, rng)
	if err != nil {
		t.Fatalf("Failed to sign request: %+v", err)
	}

	err = VerifyChannelIdentityRequest(
		sig, edPub, time.Now(), ts, rsaPriv.GetPublic())
	if err != nil {
		t.Fatalf("Failed to verify request: %+v", err)
	}

}

/*func TestSignVerify_Consistency2(t *testing.T) {
	rsaPem := "-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----"
	rsaPriv, err := rsa.LoadPrivateKeyFromPem([]byte(rsaPem))
	if err != nil {
		t.Fatalf("Failed to load rsa priv key: %+v", err)
	}
	edBytes := []byte{114, 63, 254, 165, 214, 58, 119, 204, 241, 205, 66, 170,
		206, 34, 22, 218, 0, 195, 45, 242, 133, 39, 2, 148, 103, 162, 135, 33,
		186, 34, 153, 15}
	ts := time.Unix(0, int64(1659965057))

	prng := rand.New(rand.NewSource(42))

	expectedList := []string{
		"VxSJ4Ylau1Aux+XytG5lCdzcFfhESeQAdHTfs0utAVYRGXEnyK1m+7AYvCtyPbuG2tVt" +
			"vdx8JnEDxLSPDen6Od02ghwjrcEIHObfXLJ1DjbGdTsFFFxgMVtK5DBgh5ZSHDmn" +
			"NB/qWDtz3AWg+0PzWxMbMqQfyCqMwqc5BKg96+Rv/9Ncg1/qsk8Zze+W3AL99Z/D" +
			"b+HMrT+QFy58+bBJnQw0knOU5mKQujBV8B2g1Iz2N6xjeGMzzNcm90kTqrq2ig7d" +
			"2YZKC4pAd9w/iyvc691JUOsns2tkV1okcTSXc6vNQ1LO+Pzru/SwDY8kdJsJKc3s" +
			"fRta6xI/+QvB5Wb05WBg0ClTq26RjnicztKW2bLnxMKvKxgKDHNV48Fgel09fXJc" +
			"SyrfjnwyTWbK0l+ZZxJ5JMxxB55CrQ9yQwYhZIluUS+/JIn0JIklgXjIRKS2zQDq" +
			"/xMvRgCvZ0YI0edSp2nsuYMc3jiqXUxOrmqgKg0+Fhbr3r5JmOR0bQF1BYcnd2af" +
			"C+4dw7ZOltQ+T5EedkT9GQzlX3datuHYQJ3xlIZX6EqjtKA2PPXmtG4UxaG0ToGL" +
			"FE0+y1Ill9HU5JJkl4JWUjNVJgvFbZLlAJoKxCAtRx9y1h1TFdOJBo2ZJLrSnmys" +
			"9pg6MC8fXtd+Dv5lzxSMMgpzITndYOaDzY7L9X0=",
		"BpBtXAUurHiHeb+/cl22Z32JpRLWJZqp5/K8rDrfvC7SfeA6PwfB8jbyTwIASfq7mNSX" +
			"tfb8J1BkErEzbbsFSyJoIiqOv7KhMj5jywr7C+yyxNBfyzXPDLtyHZM0LK8aLL/Q" +
			"Jqnolh0HHFtQ7pPeTM6c0lC0/1SYwvtPny3/vz2bTfRa/hCwudWCHGx2Far6i9Fc" +
			"cbLjNsWu7BFb5RN+pV6orAthelFEoTsRsmoiPdQEZXtflwJqyFYskF5VHq/l/az5" +
			"Yw1/m+wK5+ZOFHEwLJWET6IBkzW8QMt+L4M2mmqWalIT36cCmeabTLwxavu9rvPL" +
			"wbUbFj8P+cECDMLgHKgawY9k/E4/+F9YqqihOEeObTJOSmULPvJmOdV/wrzt30iA" +
			"r8emtEVNrV6DSeB0vo48WsFw2NH+FNXk+2VuONwwzDpuu7SmCP/CeAXBZVWD02Nq" +
			"EMvNGVexvmUE0MNVB/8pRoF/SCtjkdMvxrxS54ztkhrn7NLSRzSvUU70lWD0/CGk" +
			"a/YdGMcOLPfx+0xPLQmRrEd4smQjn3r6P7Q1NnWenjf15xfvkHLbEgAPe2BJlDCa" +
			"AZOWZkrovsEYU6w7T/exLdGB/BUwzimH0SHQPTWhP/hFxjzxERRpHJUdG2cYh0XK" +
			"a2WtrdOSWl7QmU/UGEyNtua1ItLWgx2kRw9b5yA=",
	}
	for _, expectedB64 := range expectedList {
		expected, err := base64.StdEncoding.DecodeString(expectedB64)
		if err != nil {
			t.Fatalf("Failed to decode expected: %+v", err)
		}
		t.Log(edBytes)
		t.Log(ts)
		t.Log(rsaPriv)
		t.Log(prng)
		sig, err := SignChannelIdentityRequest(edBytes, ts, rsaPriv, prng)
		if err != nil {
			t.Fatalf("Failed to sign request: %+v", err)
		}

		if !bytes.Equal(expected, sig) {
			t.Errorf("Consistency test did not receive expected result."+
				"\nexpected: %+v\nreceived: %+v",
				expectedB64, base64.StdEncoding.EncodeToString(sig))
		}

		err = VerifyChannelIdentityRequest(
			sig, edBytes, netTime.Now(), ts, rsaPriv.GetPublic())
		if err != nil {
			t.Fatalf("Failed to verify request: %+v", err)
		}
	}
}*/
