package transport

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

var (
	shortMsgTypeCodes = map[string]byte{
		"addr":         1,
		"block":        2,
		"blocktxn":     3,
		"cmpctblock":   4,
		"feefilter":    5,
		"filteradd":    6,
		"filterclear":  7,
		"filterload":   8,
		"getblocks":    9,
		"getblocktxn":  10,
		"getdata":      11,
		"getheaders":   12,
		"headers":      13,
		"inv":          14,
		"mempool":      15,
		"merkleblock":  16,
		"notfound":     17,
		"ping":         18,
		"pong":         19,
		"sendcmpct":    20,
		"tx":           21,
		"getcfilters":  22,
		"cfilter":      23,
		"getcfheaders": 24,
		"cfheaders":    25,
		"getcfcheckpt": 26,
		"cfcheckpt":    27,
		"addrv2":       28,
	}
)

type P2pMessage struct {
	Type    string
	Payload []byte
}

func NewP2pMessageFromV2Buffer(msg []byte) (*P2pMessage, error) {
	var res P2pMessage
	code := msg[0]
	if code >= 1 && int(code) <= len(shortMsgTypeCodes) {
		t := ""
		for k, v := range shortMsgTypeCodes {
			if code == v {
				t = k
				break
			}
		}
		if t == "" {
			return nil, fmt.Errorf("didn't find msgType for code: %d", code)
		}

		res.Type = t
		res.Payload = msg[1:]
	} else {
		res.Type = string(bytes.TrimRight(msg[1:13], "\x00"))
		res.Payload = msg[13:]
	}

	return &res, nil
}

func (m *P2pMessage) EncodeAsV1() []byte {
	var res []byte
	res = append(res, []byte(m.Type)...)
	res = append(res, make([]byte, 12-len(m.Type))...)

	payloadLen := uint32(len(m.Payload))
	lenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBytes, payloadLen)
	res = append(res, lenBytes...)

	payloadHash := DoubleHashB(m.Payload)
	res = append(res, payloadHash[:4]...)
	res = append(res, m.Payload...)

	return res
}

func (m *P2pMessage) EncodeAsV2() []byte {
	var res []byte
	if code, found := shortMsgTypeCodes[m.Type]; found {
		res = append([]byte{code}, m.Payload...)
	} else {
		// todo: replace with better make() and copy()
		res = append([]byte{0}, []byte(m.Type)...)
		res = append(res, make([]byte, 12-len(m.Type))...)
		res = append(res, m.Payload...)
	}
	return res
}

// DoubleHashB calculates hash(hash(b)) and returns the resulting bytes.
func DoubleHashB(b []byte) []byte {
	first := sha256.Sum256(b)
	second := sha256.Sum256(first[:])
	return second[:]
}
