package testkeys

import (
	"path/filepath"
	"runtime"
)

func getDirForFile() string {
	// Get the filename we're in
	_, currentFile, _, _ := runtime.Caller(0)
	return filepath.Dir(currentFile)
}

// These functions are used to cover TLS connection code in tests
func GetTestCertPath() string {
	return filepath.Join(getDirForFile(), "cmix.rip.crt")
}
