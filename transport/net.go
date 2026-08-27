package transport

import (
	"fmt"
	"io"
	"net"

	"github.com/rs/zerolog/log"
)

func WriteData(conn net.Conn, data []byte) error {
	if conn == nil {
		return fmt.Errorf("connection is nil")
	}
	log.Trace().Msgf("WriteData len(%d)", len(data))

	totalSent := 0
	for totalSent < len(data) {
		n, err := conn.Write(data[totalSent:])
		if err != nil {
			return err
		}
		if n <= 0 || n > len(data)-totalSent {
			return io.ErrShortWrite
		}
		totalSent += n
	}
	return nil
}

func ReadData(nc net.Conn, length int) ([]byte, error) {
	if nc == nil {
		return nil, fmt.Errorf("connection is nil")
	}
	if length < 0 {
		return nil, fmt.Errorf("negative read length: %d", length)
	}
	if length != 1 {
		log.Trace().Msgf("ReadData len: %d", length)
	}

	payload := make([]byte, length)
	_, err := io.ReadFull(nc, payload)
	if err != nil {
		return nil, err
	}
	return payload, nil
}
