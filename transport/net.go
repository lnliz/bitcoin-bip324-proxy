package transport

import (
	"fmt"
	"github.com/rs/zerolog/log"
	"net"
)

func WriteData(conn net.Conn, data []byte) error {
	log.Trace().Msgf("WriteData len(%d)", len(data))

	totalSent := 0
	for totalSent < len(data) {
		n, err := conn.Write(data[totalSent:])
		if err != nil {
			return err
		}
		totalSent += n
	}
	return nil
}

func ReadData(nc net.Conn, length int) ([]byte, error) {
	if length != 1 {
		log.Trace().Msgf("ReadData len: %d", length)
	}

	payload := make([]byte, length)
	totalBytes := 0
	for totalBytes < length {
		readBuf := make([]byte, 1)
		nn, err := nc.Read(readBuf)
		if err != nil {
			return nil, err
		}
		if nn != len(readBuf) {
			return nil, fmt.Errorf("length mismatch")
		}
		payload[totalBytes] = readBuf[0]
		totalBytes++
	}
	return payload, nil
}
