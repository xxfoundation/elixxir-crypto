////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

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

func GetTestKeyPath() string {
	return filepath.Join(getDirForFile(), "cmix.rip.key")
}
