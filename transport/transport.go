package transport

import (
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"

	bip324_crypto "github.com/lnliz/bitcoin-bip324-proxy/crypto"

	"github.com/btcsuite/btcd/wire"
	"github.com/rs/zerolog/log"
)

const (
	MaxGarbageLength = 4095
)

var (
	ErrV1Handshake       = errors.New("v1 handshake prefix received")
	ErrWrongNetworkV1    = errors.New("wrong-network v1 handshake prefix received")
	ErrGarbageTerminator = errors.New("garbage terminator not found")
	v1VersionMsgCommand  = []byte("version\x00\x00\x00\x00\x00")

	shortMsgCommands = [...]string{
		"",
		"addr", "block", "blocktxn", "cmpctblock", "feefilter",
		"filteradd", "filterclear", "filterload", "getblocks",
		"getblocktxn", "getdata", "getheaders", "headers", "inv",
		"mempool", "merkleblock", "notfound", "ping", "pong",
		"sendcmpct", "tx", "getcfilters", "cfilter", "getcfheaders",
		"cfheaders", "getcfcheckpt", "cfcheckpt", "addrv2",
		"uproof", "getuproof", "uttls", "getuttls", "usummary",
		"utreexotx", "uroot", "geturoot", "feature",
	}
	shortMsgCmdCodes = makeShortMessageCodeMap()
)

type V2Transport struct {
	remoteCon      net.Conn
	cipher         *bip324_crypto.Bip324Cipher
	btcNet         uint32
	isInitializing bool

	SendAadAndGarbage []byte
	RecvAad           []byte

	receivedPrefix []byte
	sendMu         sync.Mutex
	recvMu         sync.Mutex
	handshakeMu    sync.Mutex
	handshakeTried bool
}

func NewTransport(remoteCon net.Conn, btcNet uint32, isInitializing bool) (*V2Transport, error) {
	if remoteCon == nil {
		return nil, fmt.Errorf("connection is nil")
	}
	return newTransport(remoteCon, btcNet, isInitializing, nil)
}

func NewTransportWithCipher(remoteCon net.Conn, btcNet uint32, isInitializing bool, cipher *bip324_crypto.Bip324Cipher) (*V2Transport, error) {
	if remoteCon == nil {
		return nil, fmt.Errorf("connection is nil")
	}
	if cipher == nil {
		return nil, fmt.Errorf("cipher is nil")
	}
	if cipher.NetworkMagic() != btcNet {
		return nil, fmt.Errorf("cipher network magic 0x%08x does not match transport network magic 0x%08x", cipher.NetworkMagic(), btcNet)
	}
	return newTransport(remoteCon, btcNet, isInitializing, cipher)
}

func newTransport(remoteCon net.Conn, btcNet uint32, isInitializing bool, cipher *bip324_crypto.Bip324Cipher) (*V2Transport, error) {
	garbage, err := randomBytesUpTo(MaxGarbageLength)
	if err != nil {
		return nil, fmt.Errorf("generate handshake garbage: %w", err)
	}

	return &V2Transport{
		btcNet:            btcNet,
		isInitializing:    isInitializing,
		cipher:            cipher,
		remoteCon:         remoteCon,
		SendAadAndGarbage: garbage,
	}, nil
}

func EncodeWireMessageAsV2(m wire.Message) ([]byte, error) {
	if m == nil {
		return nil, fmt.Errorf("wire message is nil")
	}
	var buffer bytes.Buffer
	if err := m.BtcEncode(&buffer, wire.ProtocolVersion, wire.LatestEncoding); err != nil {
		return nil, err
	}
	if buffer.Len() > int(m.MaxPayloadLength(wire.ProtocolVersion)) {
		return nil, fmt.Errorf("%s payload is too large: %d > %d", m.Command(), buffer.Len(), m.MaxPayloadLength(wire.ProtocolVersion))
	}
	return EncodeBufAsV2(m.Command(), buffer.Bytes())
}

func EncodeBufAsV2(cmd string, buf []byte) ([]byte, error) {
	if err := validateCommand(cmd); err != nil {
		return nil, err
	}

	code, short := shortMsgCmdCodes[cmd]
	messageTypeLength := 1 + wire.CommandSize
	if short {
		messageTypeLength = 1
	}
	if len(buf) > bip324_crypto.MaxPacketContentLength-messageTypeLength {
		return nil, fmt.Errorf(
			"v2 application payload is too large: message type and %d-byte payload exceed %d bytes",
			len(buf), bip324_crypto.MaxPacketContentLength,
		)
	}

	if short {
		res := make([]byte, len(buf)+1)
		res[0] = code
		copy(res[1:], buf)
		return res, nil
	}

	res := make([]byte, 1+wire.CommandSize+len(buf))
	copy(res[1:], cmd)
	copy(res[1+wire.CommandSize:], buf)
	return res, nil
}

func decodeV2MessageType(buf []byte) (string, []byte, error) {
	if len(buf) == 0 {
		return "", nil, fmt.Errorf("empty v2 message payload")
	}

	code := buf[0]
	if code == 0 {
		if len(buf) < 1+wire.CommandSize {
			return "", nil, fmt.Errorf("v2 long-format message too short: %d bytes", len(buf))
		}
		cmd, err := decodeCommand(buf[1 : 1+wire.CommandSize])
		if err != nil {
			return "", nil, fmt.Errorf("invalid v2 command: %w", err)
		}
		return cmd, buf[1+wire.CommandSize:], nil
	}

	if int(code) < len(shortMsgCommands) && shortMsgCommands[code] != "" {
		return shortMsgCommands[code], buf[1:], nil
	}

	return "", nil, fmt.Errorf("unknown v2 short message id: %d", code)
}

func makeShortMessageCodeMap() map[string]byte {
	codes := make(map[string]byte, len(shortMsgCommands)-1)
	for code, command := range shortMsgCommands[1:] {
		codes[command] = byte(code + 1)
	}
	return codes
}

func (t *V2Transport) SendV2Message(msg wire.Message) error {
	if t == nil {
		return fmt.Errorf("transport is nil")
	}
	buf, err := EncodeWireMessageAsV2(msg)
	if err != nil {
		return err
	}
	log.Trace().Msgf("SendV2Message %s", msg.Command())
	return t.SendBip324Packet(t.remoteCon, buf, false)
}

func (t *V2Transport) SendV2MessageBuf(cmd string, buf []byte) error {
	if t == nil {
		return fmt.Errorf("transport is nil")
	}
	encoded, err := EncodeBufAsV2(cmd, buf)
	if err != nil {
		return err
	}
	return t.SendBip324Packet(t.remoteCon, encoded, false)
}

func (t *V2Transport) ReceivedPrefix() []byte {
	if t == nil {
		return nil
	}
	return append([]byte(nil), t.receivedPrefix...)
}

// SessionID returns the BIP324 channel-binding identifier after key exchange.
func (t *V2Transport) SessionID() []byte {
	if t == nil || t.cipher == nil {
		return nil
	}
	return t.cipher.SessionID()
}

// Destroy releases reachable cipher state. It must not run concurrently with
// packet or handshake operations.
func (t *V2Transport) Destroy() {
	if t == nil {
		return
	}
	if t.cipher != nil {
		t.cipher.Destroy()
		t.cipher = nil
	}
	clear(t.SendAadAndGarbage)
	clear(t.RecvAad)
	clear(t.receivedPrefix)
	t.SendAadAndGarbage = nil
	t.RecvAad = nil
	t.receivedPrefix = nil
}

func (t *V2Transport) lookForGarbage(nc net.Conn) error {
	log.Trace().Msgf("lookForGarbage")
	garbageReceived, err := ReadData(nc, bip324_crypto.GarbageTerminatorLength)
	if err != nil {
		return err
	}

	for garbageLen := 0; garbageLen <= MaxGarbageLength; garbageLen++ {
		cmp := garbageReceived[len(garbageReceived)-bip324_crypto.GarbageTerminatorLength:]
		if bytes.Equal(cmp, t.cipher.RecvGarbageTerminator) {
			t.RecvAad = append(t.RecvAad[:0], garbageReceived[:len(garbageReceived)-bip324_crypto.GarbageTerminatorLength]...)
			return nil
		}
		if garbageLen == MaxGarbageLength {
			return fmt.Errorf("%w after %d bytes", ErrGarbageTerminator, MaxGarbageLength)
		}
		oneByte, err := ReadData(nc, 1)
		if err != nil {
			return err
		}
		garbageReceived = append(garbageReceived, oneByte...)
	}

	return ErrGarbageTerminator
}

func (t *V2Transport) MaybeSendDecoyPackets() (int, error) {
	if t == nil {
		return 0, fmt.Errorf("transport is nil")
	}
	if t.cipher == nil || !t.cipher.Initialized() {
		return 0, fmt.Errorf("transport cipher is not initialized")
	}
	packetsSent := 0

	// Policy: a 25% chance to send 1-25 decoys during the handshake.
	x, err := randomInt(100)
	if err != nil {
		return packetsSent, err
	}
	if x < 75 {
		log.Trace().Msgf("MaybeSendDecoyPackets packetsSent: %d", packetsSent)
		return packetsSent, nil
	}

	for n := 0; n < x-74; n++ {
		decoyData, err := randomBytesUpTo(249)
		if err != nil {
			return packetsSent, err
		}
		if err := t.SendBip324Packet(t.remoteCon, decoyData, true); err != nil {
			return packetsSent, err
		}
		packetsSent += 1
	}
	log.Trace().Msgf("MaybeSendDecoyPackets packetsSent: %d", packetsSent)

	return packetsSent, nil
}

// SendBip324Packet sends one encrypted packet. Any returned error is fatal to
// the channel: callers must close the connection rather than retrying it.
func (t *V2Transport) SendBip324Packet(nc net.Conn, packet []byte, ignore bool) error {
	if t == nil || t.cipher == nil {
		return fmt.Errorf("transport is not initialized")
	}
	if nc == nil {
		return fmt.Errorf("connection is nil")
	}
	t.sendMu.Lock()
	defer t.sendMu.Unlock()

	encrPacket, err := t.cipher.EncryptPacketBuf(packet, t.SendAadAndGarbage, ignore)
	if err != nil {
		return err
	}
	t.SendAadAndGarbage = []byte{}

	return WriteData(nc, encrPacket)
}

// RecvBip324Packet receives the next non-decoy packet. Any returned error is
// fatal to the channel because packet cipher state cannot be resynchronized.
func (t *V2Transport) RecvBip324Packet(nc net.Conn) ([]byte, error) {
	if t == nil || t.cipher == nil {
		return nil, fmt.Errorf("transport is not initialized")
	}
	if nc == nil {
		return nil, fmt.Errorf("connection is nil")
	}
	t.recvMu.Lock()
	defer t.recvMu.Unlock()

	log.Trace().Msgf("RecvBip324Packet")
	for {
		encrLen, err := ReadData(nc, bip324_crypto.LengthFieldLength)
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
		if packetIsIgnored(header) {
			log.Trace().Msgf("RecvBip324Packet - skipping a decoy packet with ignore bit")
			// skipping a decoy packet with ignore bit
		} else {
			log.Trace().Msgf("RecvBip324Packet DONE")
			return plaintext[1:], nil
		}
	}
}

func packetIsIgnored(header byte) bool {
	return header&bip324_crypto.HeaderIgnoreBit != 0
}

func DecodeWireMessageFromBuf(cmd string, buf []byte) (wire.Message, error) {
	res, err := makeEmptyWireMessage(cmd)
	if err != nil {
		return nil, err
	}
	if len(buf) > int(res.MaxPayloadLength(wire.ProtocolVersion)) {
		return nil, fmt.Errorf("%s payload is too large: %d > %d", cmd, len(buf), res.MaxPayloadLength(wire.ProtocolVersion))
	}

	bb := bytes.NewBuffer(buf)
	if err := res.BtcDecode(bb, wire.ProtocolVersion, wire.LatestEncoding); err != nil {
		return nil, err
	}
	if bb.Len() != 0 {
		return nil, fmt.Errorf("extra bytes after %s message: %d", cmd, bb.Len())
	}

	return res, nil
}

func (t *V2Transport) RecvV2Message() (wire.Message, string, []byte, error) {
	if t == nil {
		return nil, "", nil, fmt.Errorf("transport is nil")
	}
	log.Trace().Msgf("RecvV2Message")
	p2pMessage, err := t.RecvV2P2pMessage()
	if err != nil {
		return nil, "", nil, err
	}

	msg, err := DecodeWireMessageFromBuf(p2pMessage.Type, p2pMessage.Payload)
	log.Trace().Msgf("RecvV2Message DONE")
	return msg, p2pMessage.Type, p2pMessage.Payload, err
}

// RecvV2P2pMessage receives and frames a v2 application message without
// interpreting its payload. This is the appropriate API for transparent
// relays, which must not reject messages merely because their local wire
// library does not understand them.
func (t *V2Transport) RecvV2P2pMessage() (*P2pMessage, error) {
	if t == nil {
		return nil, fmt.Errorf("transport is nil")
	}
	buf, err := t.RecvBip324Packet(t.remoteCon)
	if err != nil {
		return nil, err
	}
	return NewP2pMessageFromV2Buffer(buf)
}

func (t *V2Transport) receiveTransportVersion() error {
	_, err := t.RecvBip324Packet(t.remoteCon)
	return err
}

func (t *V2Transport) V2Handshake() error {
	if t == nil || t.remoteCon == nil {
		return fmt.Errorf("transport is not initialized")
	}
	t.handshakeMu.Lock()
	if t.handshakeTried {
		t.handshakeMu.Unlock()
		return fmt.Errorf("v2 handshake has already been attempted")
	}
	t.handshakeTried = true
	t.handshakeMu.Unlock()
	handshakeComplete := false
	defer func() {
		if !handshakeComplete && t.cipher != nil {
			t.cipher.Destroy()
			t.cipher = nil
		}
	}()

	var receivedPrefix []byte

	if t.isInitializing {
		if err := t.ensureCipher(); err != nil {
			return err
		}
		if err := t.sendOurEllswiftPubKey(); err != nil {
			return err
		}

		if err := WriteData(t.remoteCon, t.SendAadAndGarbage); err != nil {
			return fmt.Errorf("WriteData(SendAadAndGarbage) err: %w", err)
		}
	} else {
		prefix, err := t.receiveResponderPrefix()
		if err != nil {
			return err
		}
		receivedPrefix = prefix

		if err := t.ensureCipher(); err != nil {
			return err
		}
		if err := t.sendOurEllswiftPubKey(); err != nil {
			return err
		}

		if err := WriteData(t.remoteCon, t.SendAadAndGarbage); err != nil {
			return fmt.Errorf("WriteData(SendAadAndGarbage) err: %w", err)
		}
	}

	if err := t.recvTheirEllswiftPubKey(receivedPrefix); err != nil {
		return fmt.Errorf("recvTheirEllswiftPubKey() err: %w", err)
	}

	if err := WriteData(t.remoteCon, t.cipher.SendGarbageTerminator); err != nil {
		return fmt.Errorf("WriteData(SendGarbageTerminator) err: %w", err)
	}

	if _, err := t.MaybeSendDecoyPackets(); err != nil {
		return fmt.Errorf("MaybeSendDecoyPackets() err: %w", err)
	}

	if err := t.SendBip324Packet(t.remoteCon, []byte(bip324_crypto.TransportVersion), false); err != nil {
		return fmt.Errorf("SendBip324Packet(TransportVersion) err: %w", err)
	}

	if err := t.lookForGarbage(t.remoteCon); err != nil {
		return fmt.Errorf("lookForGarbage() err: %w", err)
	}

	if err := t.receiveTransportVersion(); err != nil {
		return fmt.Errorf("receive transport version: %w", err)
	}

	handshakeComplete = true
	return nil
}

func (t *V2Transport) ensureCipher() error {
	if t.cipher != nil {
		return nil
	}

	cipher, err := bip324_crypto.NewBip324Cipher(t.btcNet)
	if err != nil {
		return fmt.Errorf("create BIP324 cipher: %w", err)
	}
	t.cipher = cipher
	return nil
}

func (t *V2Transport) sendOurEllswiftPubKey() error {
	log.Trace().Msgf("sendOurEllswiftPubKey")
	publicKey := t.cipher.GetOurEllswiftPublicKey()
	if len(publicKey) != bip324_crypto.EllswiftPubKeyLength {
		return fmt.Errorf("local ellswift public key has invalid length: %d", len(publicKey))
	}
	return WriteData(t.remoteCon, publicKey)
}

func (t *V2Transport) receiveResponderPrefix() ([]byte, error) {
	v1Prefix := t.v1Prefix()
	receivedPrefix := make([]byte, 0, len(v1Prefix))
	t.receivedPrefix = t.receivedPrefix[:0]

	for len(receivedPrefix) < len(v1Prefix) {
		oneByte, err := ReadData(t.remoteCon, 1)
		if err != nil {
			return nil, err
		}

		receivedPrefix = append(receivedPrefix, oneByte[0])
		t.receivedPrefix = append(t.receivedPrefix, oneByte[0])
		lastIdx := len(receivedPrefix) - 1
		if receivedPrefix[lastIdx] != v1Prefix[lastIdx] {
			return receivedPrefix, nil
		}
	}

	return receivedPrefix, ErrV1Handshake
}

func (t *V2Transport) v1Prefix() []byte {
	var magic [4]byte
	binary.LittleEndian.PutUint32(magic[:], t.btcNet)

	prefix := make([]byte, 0, len(magic)+len(v1VersionMsgCommand))
	prefix = append(prefix, magic[:]...)
	prefix = append(prefix, v1VersionMsgCommand...)
	return prefix
}

func (t *V2Transport) recvTheirEllswiftPubKey(receivedPrefix []byte) error {
	log.Trace().Msgf("recvTheirEllswiftPubKey")
	maxPrefixLength := 0
	if !t.isInitializing {
		maxPrefixLength = len(t.v1Prefix())
	}
	if len(receivedPrefix) > maxPrefixLength {
		return fmt.Errorf("received prefix too large for transport role: %d > %d", len(receivedPrefix), maxPrefixLength)
	}

	theirEllswiftPubKey := append([]byte(nil), receivedPrefix...)
	remainingLen := bip324_crypto.EllswiftPubKeyLength - len(receivedPrefix)
	remainder, err := ReadData(t.remoteCon, remainingLen)
	if err != nil {
		return err
	}
	theirEllswiftPubKey = append(theirEllswiftPubKey, remainder...)

	if !t.isInitializing && bytes.Equal(theirEllswiftPubKey[4:16], t.v1Prefix()[4:16]) {
		return ErrWrongNetworkV1
	}

	if err := t.cipher.Init(theirEllswiftPubKey, t.isInitializing); err != nil {
		return err
	}

	return nil
}

func randomBytesUpTo(maxLen int) ([]byte, error) {
	if maxLen < 0 {
		return nil, fmt.Errorf("negative maximum random byte length: %d", maxLen)
	}

	sz, err := randomInt(maxLen + 1)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, sz)
	if _, err := crand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func randomInt(max int) (int, error) {
	if max <= 0 {
		return 0, fmt.Errorf("random upper bound must be positive: %d", max)
	}

	n, err := crand.Int(crand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}
