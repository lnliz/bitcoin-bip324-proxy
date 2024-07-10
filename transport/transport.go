package transport

import (
	"bytes"
	crand "crypto/rand"
	"fmt"
	"github.com/rs/zerolog"
	"math/rand"
	"net"

	bip324_crypto "github.com/lnliz/bitcoin-bip324-proxy/crypto"

	"github.com/btcsuite/btcd/wire"
	"github.com/rs/zerolog/log"
)

const (
	maxGarbageLength = 4096
)

var (
	shortMsgCmdCodes = map[string]byte{
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

func init() {
	zerolog.SetGlobalLevel(zerolog.TraceLevel)
	log.Trace().Msgf("LFG")
}

type V2Transport struct {
	remoteCon      net.Conn
	cipher         *bip324_crypto.Bip324Cipher
	btcNet         uint32
	isInitializing bool

	SendAadAndGarbage []byte
	RecvAad           []byte
}

func NewTransport(remoteCon net.Conn, btcNet uint32, isInitializing bool) (*V2Transport, error) {
	cipher, err := bip324_crypto.NewBip324Cipher(btcNet)
	if err != nil {
		return nil, err
	}
	return NewTransportWithCipher(remoteCon, btcNet, isInitializing, cipher), nil
}

func NewTransportWithCipher(remoteCon net.Conn, btcNet uint32, isInitializing bool, cipher *bip324_crypto.Bip324Cipher) *V2Transport {
	return &V2Transport{
		btcNet:            btcNet,
		isInitializing:    isInitializing,
		cipher:            cipher,
		remoteCon:         remoteCon,
		SendAadAndGarbage: getRandomBytes(maxGarbageLength),
	}
}

func EncodeWireMessageAsV2(m wire.Message) ([]byte, error) {
	var buffer bytes.Buffer
	if err := m.BtcEncode(&buffer, wire.ProtocolVersion, wire.LatestEncoding); err != nil {
		return nil, err
	}
	return EncodeBufAsV2(m.Command(), buffer.Bytes()), nil
}

func EncodeBufAsV2(cmd string, buf []byte) []byte {
	if code, found := shortMsgCmdCodes[cmd]; found {
		res := make([]byte, len(buf)+1)
		res[0] = code
		copy(res[1:], buf)
		return res
	} else {
		res := make([]byte, 1+23+len(buf))
		copy(res[1:], cmd)
		copy(res[12+1:], buf)
		return res
	}
}

func (t *V2Transport) SendV2Message(msg wire.Message) error {
	log.Trace().Msgf("SendV2Message %s", msg.Command())
	buf, err := EncodeWireMessageAsV2(msg)
	if err != nil {
		return err
	}
	return t.SendBip324Packet(t.remoteCon, buf, false)
}

func (t *V2Transport) SendV2MessageBuf(cmd string, buf []byte) error {
	return t.SendBip324Packet(t.remoteCon, EncodeBufAsV2(cmd, buf), false)
}

func (t *V2Transport) lookForGarbage(nc net.Conn) error {
	log.Trace().Msgf("lookForGarbage")
	garbageReceived, err := ReadData(nc, bip324_crypto.GarbageTerminatorLength)
	if err != nil {
		return err
	}

	terminatorFound := false
	for n := 0; n < maxGarbageLength; n++ {
		cmp := garbageReceived[len(garbageReceived)-bip324_crypto.GarbageTerminatorLength:]
		if bytes.Equal(cmp, t.cipher.RecvGarbageTerminator) {
			terminatorFound = true
			break
		}
		oneByte, err := ReadData(nc, 1)
		if err != nil {
			return err
		}
		garbageReceived = append(garbageReceived, oneByte...)
	}

	if !terminatorFound {
		return fmt.Errorf("initiatorGarbage terminator not found, we're done")
	}

	// strip terminator from result
	garbageReceived = garbageReceived[:len(garbageReceived)-bip324_crypto.GarbageTerminatorLength]
	t.RecvAad = garbageReceived

	return nil
}

func (t *V2Transport) MaybeSendDecoyPackets() (int, error) {
	packetsSent := 0

	// todo: allow configure how often decoy is sent
	// current config: 25% chance to send 1-25 decoys
	x := rand.Intn(100)
	for n := 75; n < x; n++ {
		decoyData := getRandomBytes(250)
		if err := t.SendBip324Packet(t.remoteCon, decoyData, true); err != nil {
			return packetsSent, err
		}
		packetsSent += 1
	}
	log.Trace().Msgf("MaybeSendDecoyPackets packetsSent: %d", packetsSent)

	return packetsSent, nil
}

func (t *V2Transport) SendBip324Packet(nc net.Conn, packet []byte, ignore bool) error {
	encrPacket, err := t.cipher.EncryptPacketBuf(packet, t.SendAadAndGarbage, ignore)
	if err != nil {
		return err
	}
	t.SendAadAndGarbage = []byte{}

	return WriteData(nc, encrPacket)
}

func (t *V2Transport) RecvBip324Packet(nc net.Conn) ([]byte, error) {
	log.Trace().Msgf("RecvBip324Packet")
	for {
		encrLen, err := ReadData(nc, 3)
		if err != nil {
			return nil, err
		}

		length, err := t.cipher.DecryptPacketLen(encrLen)
		if err != nil {
			return nil, err
		}

		expectedPayloadLen := 1 + length + bip324_crypto.Expansion
		aeadCiphertext, err := ReadData(nc, expectedPayloadLen)
		if err != nil {
			log.Trace().Msgf("RecvBip324Packet err: %s", err.Error())
			return nil, err
		}

		plaintext, err := t.cipher.DecryptPacketBuf(aeadCiphertext, t.RecvAad)
		if err != nil {
			log.Trace().Msgf("RecvBip324Packet DecryptPacketBuf err: %s", err.Error())
			return nil, err
		}

		t.RecvAad = []byte{}

		header := plaintext[0]
		if header&bip324_crypto.HeaderIgnoreBit == bip324_crypto.HeaderIgnoreBit {
			log.Trace().Msgf("RecvBip324Packet - skipping a decoy packet with ignore bit")
			// skipping a decoy packet with ignore bit
		} else {
			log.Trace().Msgf("RecvBip324Packet DONE")
			return plaintext[1 : length+1], nil
		}
	}
}

func DecodeWireMessageFromBuf(cmd string, buf []byte) (wire.Message, error) {
	res, err := makeEmptyWireMessage(cmd)
	if err != nil {
		return nil, err
	}

	bb := bytes.NewBuffer(buf)
	if err := res.BtcDecode(bb, wire.ProtocolVersion, wire.LatestEncoding); err != nil {
		return nil, err
	}

	return res, nil
}

func (t *V2Transport) RecvV2Message() (wire.Message, string, []byte, error) {
	log.Trace().Msgf("RecvV2Message")
	buf, err := t.RecvBip324Packet(t.remoteCon)
	if err != nil {
		return nil, "", nil, err
	}

	cmd := ""
	code := buf[0]
	if code >= 1 && int(code) <= len(shortMsgCmdCodes) {
		for k, v := range shortMsgCmdCodes {
			if code == v {
				cmd = k
				break
			}
		}
		if cmd == "" {
			return nil, "", nil, fmt.Errorf("didn't find msgType for code: %d", code)
		}

		buf = buf[1:]
	} else {
		cmd = string(bytes.TrimRight(buf[1:13], "\x00"))
		buf = buf[13:]
	}

	msg, err := DecodeWireMessageFromBuf(cmd, buf)
	log.Trace().Msgf("RecvV2Message DONE")
	return msg, cmd, buf, err
}

func (t *V2Transport) receiveAndCheckTransportVersion() error {
	peerTransportVersion, err := t.RecvBip324Packet(t.remoteCon)
	if err != nil {
		return err
	}

	if !bytes.Equal(peerTransportVersion, bip324_crypto.TransportVersion) {
		return fmt.Errorf("unexpected peerTransportVersion: %#v", peerTransportVersion)
	}
	return nil
}

func (t *V2Transport) V2Handshake() error {
	/*
		try to establish an encrypted v2 connection
	*/
	if err := t.sendOurEllswiftPubKey(); err != nil {
		return err
	}

	if t.isInitializing {
		if err := WriteData(t.remoteCon, t.SendAadAndGarbage); err != nil {
			return fmt.Errorf("WriteData(SendAadAndGarbage) err: %w", err)
		}
	}

	/*
		receive their ellswift key and initialize our cipher
	*/
	if err := t.recvTheirEllswiftPubKey(); err != nil {
		return fmt.Errorf("recvTheirEllswiftPubKey() err: %w", err)
	}

	if t.isInitializing {
		if err := WriteData(t.remoteCon, t.cipher.SendGarbageTerminator); err != nil {
			return fmt.Errorf("WriteData(SendGarbageTerminator) err: %w", err)
		}

		if _, err := t.MaybeSendDecoyPackets(); err != nil {
			return fmt.Errorf("MaybeSendDecoyPackets() err: %w", err)
		}

		if err := t.lookForGarbage(t.remoteCon); err != nil {
			return fmt.Errorf("lookForGarbage() err: %w", err)
		}
	} else {
		if err := t.lookForGarbage(t.remoteCon); err != nil {
			return fmt.Errorf("lookForGarbage() err: %w", err)
		}

		if err := WriteData(t.remoteCon, t.SendAadAndGarbage); err != nil {
			return fmt.Errorf("WriteData(SendAadAndGarbage) err: %w", err)
		}

		if err := WriteData(t.remoteCon, t.cipher.SendGarbageTerminator); err != nil {
			return fmt.Errorf("WriteData(SendGarbageTerminator) err: %w", err)
		}

		if _, err := t.MaybeSendDecoyPackets(); err != nil {
			return fmt.Errorf("MaybeSendDecoyPackets() err: %w", err)
		}
	}

	/*
		finally: check the TransportVersion
	*/
	if t.isInitializing {
		if err := t.receiveAndCheckTransportVersion(); err != nil {
			return fmt.Errorf("receiveAndCheckTransportVersion() err: %w", err)
		}

		if err := t.SendBip324Packet(t.remoteCon, bip324_crypto.TransportVersion, false); err != nil {
			return fmt.Errorf("SendBip324Packet(TransportVersion) err: %w", err)
		}
	} else {
		if err := t.SendBip324Packet(t.remoteCon, bip324_crypto.TransportVersion, false); err != nil {
			return fmt.Errorf("SendBip324Packet(TransportVersion) err: %w", err)
		}

		if err := t.receiveAndCheckTransportVersion(); err != nil {
			return fmt.Errorf("receiveAndCheckTransportVersion() err: %w", err)
		}
	}

	/*
		success: established a v2 connection
	*/
	return nil
}

func (t *V2Transport) sendOurEllswiftPubKey() error {
	log.Trace().Msgf("sendOurEllswiftPubKey")
	return WriteData(t.remoteCon, t.cipher.GetOurEllswiftPublicKey())
}

func (t *V2Transport) recvTheirEllswiftPubKey() error {
	log.Trace().Msgf("recvTheirEllswiftPubKey")
	theirEllswiftPubKey, err := ReadData(t.remoteCon, bip324_crypto.EllswiftPubKeyLength)
	if err != nil {
		return err
	}

	if err := t.cipher.Init(theirEllswiftPubKey, t.isInitializing); err != nil {
		return err
	}

	return nil
}

func getRandomBytes(maxSz int) []byte {
	sz := rand.Intn(maxSz)
	buf := make([]byte, sz)
	crand.Read(buf)
	return buf
}
