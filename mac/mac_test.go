package mac

import(
	"testing"
)

func TestMAC(t *testing.T) {
	message := []byte("Blah")
	key := []byte("Blah2")
	mac := MessageAuthenticationCode(message, key)
	if !VerifyMessageAuthenticationCode(message, key, mac) {
		t.Errorf("MAC is not working!")
	}
	expected := []byte{
		136, 145, 4, 147, 50, 117, 134, 168, 154, 75, 79, 176, 224, 26,
		122, 50, 80, 8, 57, 4, 60, 14, 178, 33, 8, 1, 111, 91, 50, 188,
		119, 42,
	}
	if len(expected) != len(mac) {
		t.Errorf("MAC has changed length: %d expected, got %d", len(expected),
			len(mac))
	}
	for i := 0; i < len(expected); i++ {
		if expected[i] != mac[i] {
			t.Errorf("MAC Byte Differs at %d: %d expected, got %d", i, expected[i],
				mac[i])
		}
	}

	// Now test sending a nil as the key
	message2 := []byte("BlahBlah2")
	mac2 := MessageAuthenticationCode(message2, nil)
	if !VerifyMessageAuthenticationCode(message2, nil, mac2) {
		t.Errorf("MAC is not working!")
	}
	if len(expected) != len(mac2) {
		t.Errorf("MAC w/ no key has changed length: %d expected, got %d",
			len(expected), len(mac2))
	}
	for i := 0; i < len(expected); i++ {
		if expected[i] != mac2[i] {
			t.Errorf("MAC w/ no key Byte Differs at %d: %d expected, got %d",
				i, expected[i], mac2[i])
		}
	}
}
