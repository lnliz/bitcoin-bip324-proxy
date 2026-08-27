package transport

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btcd/wire"
)

type P2pMessage struct {
	Type    string
	Payload []byte
}

func NewP2pMessageFromV2Buffer(msg []byte) (*P2pMessage, error) {
	cmd, payload, err := decodeV2MessageType(msg)
	if err != nil {
		return nil, err
	}

	return &P2pMessage{
		Type:    cmd,
		Payload: payload,
	}, nil
}

func (m *P2pMessage) EncodeAsV1() ([]byte, error) {
	if m == nil {
		return nil, fmt.Errorf("p2p message is nil")
	}
	return EncodeV1Message(m.Type, m.Payload)
}

func (m *P2pMessage) EncodeAsV2() ([]byte, error) {
	if m == nil {
		return nil, fmt.Errorf("p2p message is nil")
	}
	return EncodeBufAsV2(m.Type, m.Payload)
}

// EncodeV1Message returns a v1 command, length, checksum, and payload. Network
// magic is intentionally left to the caller.
func EncodeV1Message(command string, payload []byte) ([]byte, error) {
	if err := validateCommand(command); err != nil {
		return nil, err
	}
	if len(payload) > wire.MaxMessagePayload {
		return nil, fmt.Errorf("payload is too large: %d > %d", len(payload), wire.MaxMessagePayload)
	}

	result := make([]byte, wire.CommandSize+8+len(payload))
	copy(result[:wire.CommandSize], command)
	binary.LittleEndian.PutUint32(result[wire.CommandSize:wire.CommandSize+4], uint32(len(payload)))
	checksum := DoubleHashB(payload)
	copy(result[wire.CommandSize+4:wire.CommandSize+8], checksum[:4])
	copy(result[wire.CommandSize+8:], payload)
	return result, nil
}

// DecodeCommand validates and removes the zero padding from a v1 command field.
func DecodeCommand(field []byte) (string, error) {
	if len(field) != wire.CommandSize {
		return "", fmt.Errorf("command field must be %d bytes, got %d", wire.CommandSize, len(field))
	}

	end := len(field)
	for i, b := range field {
		if b == 0 {
			end = i
			for _, padding := range field[i:] {
				if padding != 0 {
					return "", fmt.Errorf("command has non-zero bytes after its terminator")
				}
			}
			break
		}
		if b < 0x20 || b > 0x7e {
			return "", fmt.Errorf("command contains non-printable ASCII byte 0x%02x", b)
		}
	}

	command := string(field[:end])
	if err := validateCommand(command); err != nil {
		return "", err
	}
	return command, nil
}

func decodeCommand(field []byte) (string, error) {
	return DecodeCommand(field)
}

func validateCommand(command string) error {
	if len(command) > wire.CommandSize {
		return fmt.Errorf("command %q is too long: %d > %d", command, len(command), wire.CommandSize)
	}
	for i := range command {
		if command[i] < 0x20 || command[i] > 0x7e {
			return fmt.Errorf("command %q contains non-printable ASCII byte 0x%02x", command, command[i])
		}
	}
	return nil
}

// DoubleHashB calculates hash(hash(b)) and returns the resulting bytes.
func DoubleHashB(b []byte) []byte {
	first := sha256.Sum256(b)
	second := sha256.Sum256(first[:])
	return second[:]
}
