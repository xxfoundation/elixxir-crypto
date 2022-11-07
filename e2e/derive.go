////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package e2e

import (
	"encoding/binary"
	"hash"
)

// derive creates a bit key from a key id and a byte slice by hashing them and
// all the passed salts with the passed hash function. it will have the size
// of the output of the hash function
func derive(h hash.Hash, data []byte, id uint32, salts ...[]byte) []byte {
	//convert the
	keyIdBytes := make([]byte, binary.MaxVarintLen32)
	n := binary.PutUvarint(keyIdBytes, uint64(id))
	h.Write(data)
	h.Write(keyIdBytes[:n])
	for _, salt := range salts {
		h.Write(salt)
	}
	return h.Sum(nil)
}
