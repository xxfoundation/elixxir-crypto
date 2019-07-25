package tls

import "testing"

func TestLoadCSR_EmptyRequest(t *testing.T) {
	csrBytes := ""
	_, err := LoadCSR(csrBytes)
	if err == nil {
		t.Error("Generated a certificate request from an empty file!")
	}

}
