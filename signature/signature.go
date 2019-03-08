package signature

import (
	"bufio"
	"bytes"
	"encoding/gob"
)

func decode(b []byte, e interface{}) error {
	reader := bufio.NewReader(b)

	dec := gob.NewDecoder(reader)

	return dec.Decode(e)
}

func encode(e interface{}) ([]byte, error) {
	var buffer bytes.Buffer

	enc := gob.NewEncoder(&buffer)

	err := enc.Encode(e)

	return buffer.Bytes(), err
}
