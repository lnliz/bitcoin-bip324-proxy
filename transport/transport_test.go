package transport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	btcdv2 "github.com/btcsuite/btcd/v2transport"
	"github.com/btcsuite/btcd/wire"
	bip324_crypto "github.com/lnliz/bitcoin-bip324-proxy/crypto"
	"github.com/rs/zerolog"
)

func TestMain(m *testing.M) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	os.Exit(m.Run())
}

func TestEncodeBufAsV2LongCommandFrame(t *testing.T) {
	payload := []byte{0xaa, 0xbb, 0xcc}
	for _, cmd := range []string{
		wire.CmdVersion,
		wire.CmdVerAck,
		wire.CmdSendAddrV2,
		"wtxidrelay",
	} {
		t.Run(cmd, func(t *testing.T) {
			got, err := EncodeBufAsV2(cmd, payload)
			if err != nil {
				t.Fatalf("EncodeBufAsV2 err: %s", err)
			}
			if len(got) != 13+len(payload) {
				t.Fatalf("len(EncodeBufAsV2) = %d, want %d", len(got), 13+len(payload))
			}
			if got[0] != 0 {
				t.Fatalf("long command marker = %d, want 0", got[0])
			}

			var wantCommand [12]byte
			copy(wantCommand[:], cmd)
			if !bytes.Equal(got[1:13], wantCommand[:]) {
				t.Fatalf("command field = %x, want %x", got[1:13], wantCommand[:])
			}
			if !bytes.Equal(got[13:], payload) {
				t.Fatalf("payload = %x, want %x", got[13:], payload)
			}
		})
	}
}

func TestDecodeV2MessageType(t *testing.T) {
	payload := []byte{0x01, 0x02}

	t.Run("empty", func(t *testing.T) {
		_, _, err := decodeV2MessageType(nil)
		if err == nil || !strings.Contains(err.Error(), "empty") {
			t.Fatalf("decodeV2MessageType err = %v, want empty error", err)
		}
	})

	t.Run("long", func(t *testing.T) {
		buf, err := EncodeBufAsV2(wire.CmdVersion, payload)
		if err != nil {
			t.Fatalf("EncodeBufAsV2 err: %s", err)
		}

		cmd, gotPayload, err := decodeV2MessageType(buf)
		if err != nil {
			t.Fatalf("decodeV2MessageType err: %s", err)
		}
		if cmd != wire.CmdVersion {
			t.Fatalf("cmd = %q, want %q", cmd, wire.CmdVersion)
		}
		if !bytes.Equal(gotPayload, payload) {
			t.Fatalf("payload = %x, want %x", gotPayload, payload)
		}
	})

	t.Run("short", func(t *testing.T) {
		buf := append([]byte{shortMsgCmdCodes[wire.CmdPing]}, payload...)

		cmd, gotPayload, err := decodeV2MessageType(buf)
		if err != nil {
			t.Fatalf("decodeV2MessageType err: %s", err)
		}
		if cmd != wire.CmdPing {
			t.Fatalf("cmd = %q, want %q", cmd, wire.CmdPing)
		}
		if !bytes.Equal(gotPayload, payload) {
			t.Fatalf("payload = %x, want %x", gotPayload, payload)
		}
	})

	t.Run("truncated long", func(t *testing.T) {
		_, _, err := decodeV2MessageType([]byte{0, 'v', 'e', 'r'})
		if err == nil || !strings.Contains(err.Error(), "too short") {
			t.Fatalf("decodeV2MessageType err = %v, want too-short error", err)
		}
	})

	t.Run("unknown short", func(t *testing.T) {
		_, _, err := decodeV2MessageType(append([]byte{255}, make([]byte, 12)...))
		if err == nil || !strings.Contains(err.Error(), "unknown v2 short message id") {
			t.Fatalf("decodeV2MessageType err = %v, want unknown-short-id error", err)
		}
	})
}

func TestV2CommandValidation(t *testing.T) {
	for _, command := range []string{
		"thirteen-byte!",
		"bad\x00command",
		"bad\ncommand",
		"non-ascii-\xff",
	} {
		t.Run(command, func(t *testing.T) {
			if _, err := EncodeBufAsV2(command, nil); err == nil {
				t.Fatalf("EncodeBufAsV2 accepted command %q", command)
			}
			if _, err := EncodeV1Message(command, nil); err == nil {
				t.Fatalf("EncodeV1Message accepted command %q", command)
			}
		})
	}

	malformedFields := [][]byte{
		{'p', 'i', 0, 'g'},
		{0x80},
	}
	for _, field := range malformedFields {
		padded := make([]byte, wire.CommandSize)
		copy(padded, field)
		if _, _, err := decodeV2MessageType(append([]byte{0}, padded...)); err == nil {
			t.Fatalf("decodeV2MessageType accepted command field %x", padded)
		}
	}
}

func TestEmptyLongCommandMatchesV1Syntax(t *testing.T) {
	payload := []byte{0xaa}
	encoded, err := EncodeBufAsV2("", payload)
	if err != nil {
		t.Fatalf("EncodeBufAsV2 empty command err: %s", err)
	}
	if len(encoded) != 1+wire.CommandSize+len(payload) || !bytes.Equal(encoded[:1+wire.CommandSize], make([]byte, 1+wire.CommandSize)) {
		t.Fatalf("empty long command encoding = %x", encoded)
	}
	command, gotPayload, err := decodeV2MessageType(encoded)
	if err != nil {
		t.Fatalf("decodeV2MessageType empty command err: %s", err)
	}
	if command != "" || !bytes.Equal(gotPayload, payload) {
		t.Fatalf("decoded empty command = (%q, %x)", command, gotPayload)
	}

	v1Encoded, err := EncodeV1Message("", payload)
	if err != nil {
		t.Fatalf("EncodeV1Message empty command err: %s", err)
	}
	if command, err := DecodeCommand(v1Encoded[:wire.CommandSize]); err != nil || command != "" {
		t.Fatalf("DecodeCommand empty command = %q, %v", command, err)
	}
}

func TestV2ApplicationLengthIncludesMessageType(t *testing.T) {
	payload := make([]byte, bip324_crypto.MaxPacketContentLength)
	if _, err := EncodeBufAsV2(wire.CmdPing, payload); err == nil {
		t.Fatalf("short-form encoder accepted a payload without room for its message type")
	}
	if _, err := EncodeBufAsV2(wire.CmdVersion, payload); err == nil {
		t.Fatalf("long-form encoder accepted a payload without room for its message type")
	}

	shortPayload := make([]byte, bip324_crypto.MaxPacketContentLength-1)
	shortEncoded, err := EncodeBufAsV2(wire.CmdPing, shortPayload)
	if err != nil || len(shortEncoded) != bip324_crypto.MaxPacketContentLength {
		t.Fatalf("maximum short-form message: len=%d err=%v", len(shortEncoded), err)
	}
	longPayload := make([]byte, bip324_crypto.MaxPacketContentLength-(1+wire.CommandSize))
	longEncoded, err := EncodeBufAsV2(wire.CmdVersion, longPayload)
	if err != nil || len(longEncoded) != bip324_crypto.MaxPacketContentLength {
		t.Fatalf("maximum long-form message: len=%d err=%v", len(longEncoded), err)
	}
}

func TestLongEncodingAcceptedForShortMessageType(t *testing.T) {
	command := make([]byte, wire.CommandSize)
	copy(command, wire.CmdPing)
	payload := []byte{1, 2, 3}
	encoded := append([]byte{0}, command...)
	encoded = append(encoded, payload...)

	gotCommand, gotPayload, err := decodeV2MessageType(encoded)
	if err != nil {
		t.Fatalf("decodeV2MessageType err: %s", err)
	}
	if gotCommand != wire.CmdPing || !bytes.Equal(gotPayload, payload) {
		t.Fatalf("decoded (%q, %x), want (%q, %x)", gotCommand, gotPayload, wire.CmdPing, payload)
	}
}

func TestShortMessageTypeTable(t *testing.T) {
	if len(shortMsgCommands) != 38 {
		t.Fatalf("short message table has %d entries, want 38", len(shortMsgCommands))
	}
	for id := 1; id < len(shortMsgCommands); id++ {
		command := shortMsgCommands[id]
		if got := shortMsgCmdCodes[command]; got != byte(id) {
			t.Fatalf("command %q has id %d, want %d", command, got, id)
		}
		encoded, err := EncodeBufAsV2(command, nil)
		if err != nil {
			t.Fatalf("EncodeBufAsV2(%q) err: %s", command, err)
		}
		if len(encoded) != 1 || encoded[0] != byte(id) {
			t.Fatalf("EncodeBufAsV2(%q) = %x, want %02x", command, encoded, id)
		}
	}
}

func TestV1MessageEncoding(t *testing.T) {
	payload := []byte{0xaa, 0xbb}
	encoded, err := EncodeV1Message("unknown", payload)
	if err != nil {
		t.Fatalf("EncodeV1Message err: %s", err)
	}
	if len(encoded) != wire.CommandSize+8+len(payload) {
		t.Fatalf("encoded length = %d", len(encoded))
	}
	command, err := DecodeCommand(encoded[:wire.CommandSize])
	if err != nil {
		t.Fatalf("DecodeCommand err: %s", err)
	}
	if command != "unknown" {
		t.Fatalf("command = %q, want unknown", command)
	}
	if got := binary.LittleEndian.Uint32(encoded[wire.CommandSize : wire.CommandSize+4]); got != uint32(len(payload)) {
		t.Fatalf("payload length = %d, want %d", got, len(payload))
	}
	if !bytes.Equal(encoded[wire.CommandSize+4:wire.CommandSize+8], DoubleHashB(payload)[:4]) {
		t.Fatalf("checksum mismatch")
	}
	if !bytes.Equal(encoded[wire.CommandSize+8:], payload) {
		t.Fatalf("payload = %x, want %x", encoded[wire.CommandSize+8:], payload)
	}
}

func TestDecodeV2MessageTypeAuxiliaryShortIDs(t *testing.T) {
	for cmd, id := range map[string]byte{
		"uproof":    29,
		"getuproof": 30,
		"uttls":     31,
		"getuttls":  32,
		"usummary":  33,
		"utreexotx": 34,
		"uroot":     35,
		"geturoot":  36,
		"feature":   37,
	} {
		t.Run(cmd, func(t *testing.T) {
			payload := []byte{0xaa}
			gotCmd, gotPayload, err := decodeV2MessageType(append([]byte{id}, payload...))
			if err != nil {
				t.Fatalf("decodeV2MessageType err: %s", err)
			}
			if gotCmd != cmd {
				t.Fatalf("cmd = %q, want %q", gotCmd, cmd)
			}
			if !bytes.Equal(gotPayload, payload) {
				t.Fatalf("payload = %x, want %x", gotPayload, payload)
			}
		})
	}
}

func TestNewP2pMessageFromV2BufferRejectsUnknownShortID(t *testing.T) {
	_, err := NewP2pMessageFromV2Buffer(append([]byte{255}, make([]byte, 12)...))
	if err == nil || !strings.Contains(err.Error(), "unknown v2 short message id") {
		t.Fatalf("NewP2pMessageFromV2Buffer err = %v, want unknown-short-id error", err)
	}
}

func TestDecodeWireMessageFromBufRejectsTrailingBytes(t *testing.T) {
	if _, err := DecodeWireMessageFromBuf(wire.CmdVerAck, nil); err != nil {
		t.Fatalf("DecodeWireMessageFromBuf valid verack err: %s", err)
	}

	_, err := DecodeWireMessageFromBuf(wire.CmdVerAck, []byte{0x00})
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("DecodeWireMessageFromBuf verack err = %v, want size error", err)
	}

	_, err = DecodeWireMessageFromBuf(wire.CmdAddr, []byte{0x00, 0x00})
	if err == nil || !strings.Contains(err.Error(), "extra bytes") {
		t.Fatalf("DecodeWireMessageFromBuf addr err = %v, want extra-bytes error", err)
	}
}

func TestDecodeWireMessageFromBufSupportsWTxIDRelay(t *testing.T) {
	message, err := DecodeWireMessageFromBuf(wire.CmdWTxIdRelay, nil)
	if err != nil {
		t.Fatalf("DecodeWireMessageFromBuf wtxidrelay err: %s", err)
	}
	if _, ok := message.(*wire.MsgWTxIdRelay); !ok {
		t.Fatalf("DecodeWireMessageFromBuf returned %T, want *wire.MsgWTxIdRelay", message)
	}
}

func TestMakeEmptyWireMessageSupportsBTCDCommands(t *testing.T) {
	commands := []string{
		wire.CmdVersion,
		wire.CmdVerAck,
		wire.CmdSendAddrV2,
		wire.CmdWTxIdRelay,
		wire.CmdGetAddr,
		wire.CmdAddr,
		wire.CmdAddrV2,
		wire.CmdGetBlocks,
		wire.CmdBlock,
		wire.CmdInv,
		wire.CmdGetData,
		wire.CmdNotFound,
		wire.CmdTx,
		wire.CmdPing,
		wire.CmdPong,
		wire.CmdGetHeaders,
		wire.CmdHeaders,
		wire.CmdMemPool,
		wire.CmdFilterAdd,
		wire.CmdFilterClear,
		wire.CmdFilterLoad,
		wire.CmdMerkleBlock,
		wire.CmdReject,
		wire.CmdSendHeaders,
		wire.CmdFeeFilter,
		wire.CmdGetCFilters,
		wire.CmdGetCFHeaders,
		wire.CmdGetCFCheckpt,
		wire.CmdCFilter,
		wire.CmdCFHeaders,
		wire.CmdCFCheckpt,
	}

	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			message, err := makeEmptyWireMessage(command)
			if err != nil {
				t.Fatalf("makeEmptyWireMessage(%q) err: %s", command, err)
			}
			if message == nil || message.Command() != command {
				t.Fatalf("makeEmptyWireMessage(%q) = %#v", command, message)
			}
		})
	}

	if _, err := makeEmptyWireMessage("futuremsg"); !errors.Is(err, wire.ErrUnknownMessage) {
		t.Fatalf("unknown message err = %v, want wire.ErrUnknownMessage", err)
	}
}

func TestReadDataShortReads(t *testing.T) {
	conn := &chunkedReadConn{
		data:     []byte("abcdef"),
		maxChunk: 2,
	}

	got, err := ReadData(conn, 6)
	if err != nil {
		t.Fatalf("ReadData err: %s", err)
	}
	if string(got) != "abcdef" {
		t.Fatalf("ReadData = %q, want %q", got, "abcdef")
	}
}

func TestReadDataPartialEOF(t *testing.T) {
	conn := &chunkedReadConn{
		data:     []byte("abc"),
		maxChunk: 2,
	}

	got, err := ReadData(conn, 5)
	if err == nil {
		t.Fatalf("ReadData err = nil, got payload %q", got)
	}
}

func TestReadDataRejectsNegativeLength(t *testing.T) {
	_, err := ReadData(&chunkedReadConn{}, -1)
	if err == nil || !strings.Contains(err.Error(), "negative read length") {
		t.Fatalf("ReadData err = %v, want negative length error", err)
	}
}

func TestResponderWaitsForV1PrefixMismatch(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	errChan := make(chan error, 1)
	go func() {
		transport, err := NewTransport(serverConn, uint32(wire.MainNet), false)
		if err != nil {
			errChan <- err
			return
		}
		errChan <- transport.V2Handshake()
	}()

	if err := clientConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline err: %s", err)
	}

	buf := make([]byte, 1)
	n, err := clientConn.Read(buf)
	if err == nil || n != 0 {
		t.Fatalf("responder sent %d byte(s) before v1 prefix mismatch, err=%v byte=%x", n, err, buf[:n])
	}

	_ = clientConn.Close()
	_ = serverConn.Close()
	<-errChan
}

func TestResponderPrefixMismatchAtEveryPosition(t *testing.T) {
	prefix := v1PrefixForNet(uint32(wire.MainNet))
	for mismatchAt := range prefix {
		t.Run(fmt.Sprintf("byte-%d", mismatchAt), func(t *testing.T) {
			input := append([]byte(nil), prefix...)
			input[mismatchAt] ^= 0x01
			conn := &chunkedReadConn{data: input, maxChunk: 1}
			transport := &V2Transport{remoteCon: conn, btcNet: uint32(wire.MainNet)}

			got, err := transport.receiveResponderPrefix()
			if err != nil {
				t.Fatalf("receiveResponderPrefix err: %s", err)
			}
			want := input[:mismatchAt+1]
			if !bytes.Equal(got, want) {
				t.Fatalf("received prefix = %x, want %x", got, want)
			}
			if !bytes.Equal(transport.ReceivedPrefix(), want) {
				t.Fatalf("stored prefix = %x, want %x", transport.ReceivedPrefix(), want)
			}
			if len(conn.data) != len(prefix)-mismatchAt-1 {
				t.Fatalf("consumed bytes after mismatch: %d remain, want %d", len(conn.data), len(prefix)-mismatchAt-1)
			}
		})
	}
}

func TestResponderDetectsV1Prefix(t *testing.T) {
	conn := &chunkedReadConn{
		data:     v1PrefixForNet(uint32(wire.MainNet)),
		maxChunk: 1,
	}
	transport, err := NewTransport(conn, uint32(wire.MainNet), false)
	if err != nil {
		t.Fatalf("NewTransport err: %s", err)
	}

	err = transport.V2Handshake()
	if !errors.Is(err, ErrV1Handshake) {
		t.Fatalf("V2Handshake err = %v, want ErrV1Handshake", err)
	}
	if !bytes.Equal(transport.ReceivedPrefix(), v1PrefixForNet(uint32(wire.MainNet))) {
		t.Fatalf("ReceivedPrefix = %x, want v1 prefix", transport.ReceivedPrefix())
	}
	if transport.cipher != nil {
		t.Fatalf("responder generated an ephemeral key before detecting v1")
	}
}

func TestResponderDetectsWrongNetworkV1Prefix(t *testing.T) {
	keyLikeV1Message := append(v1PrefixForNet(uint32(wire.TestNet3)), make([]byte, bip324_crypto.EllswiftPubKeyLength-16)...)
	conn := &chunkedReadConn{
		data:     keyLikeV1Message,
		maxChunk: 64,
	}
	transport, err := NewTransport(conn, uint32(wire.MainNet), false)
	if err != nil {
		t.Fatalf("NewTransport err: %s", err)
	}

	err = transport.V2Handshake()
	if !errors.Is(err, ErrWrongNetworkV1) {
		t.Fatalf("V2Handshake err = %v, want ErrWrongNetworkV1", err)
	}
	if transport.cipher != nil {
		t.Fatalf("failed wrong-network handshake retained cipher state")
	}
}

func TestHandshakeFailureDestroysCipherState(t *testing.T) {
	local, peer := net.Pipe()
	_ = peer.Close()
	defer func() { _ = local.Close() }()

	transport, err := NewTransport(local, uint32(wire.MainNet), true)
	if err != nil {
		t.Fatalf("NewTransport: %s", err)
	}
	if err := transport.V2Handshake(); err == nil {
		t.Fatalf("V2Handshake succeeded against a closed peer")
	}
	if transport.cipher != nil || transport.SessionID() != nil {
		t.Fatalf("failed handshake retained cipher state")
	}
}

func TestReceiveTransportVersionAcceptsNonEmptyReservedContents(t *testing.T) {
	initiatorCipher, responderCipher := initializedCipherPair(t)
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	initiator, err := NewTransportWithCipher(clientConn, uint32(wire.MainNet), true, initiatorCipher)
	if err != nil {
		t.Fatalf("NewTransportWithCipher initiator err: %s", err)
	}
	initiator.SendAadAndGarbage = nil
	responder, err := NewTransportWithCipher(serverConn, uint32(wire.MainNet), false, responderCipher)
	if err != nil {
		t.Fatalf("NewTransportWithCipher responder err: %s", err)
	}
	responder.SendAadAndGarbage = nil

	errChan := make(chan error, 1)
	go func() {
		errChan <- responder.SendBip324Packet(serverConn, []byte{0x01, 0x02}, false)
	}()

	if err := initiator.receiveTransportVersion(); err != nil {
		t.Fatalf("receiveTransportVersion err: %s", err)
	}
	if err := <-errChan; err != nil {
		t.Fatalf("SendBip324Packet err: %s", err)
	}
}

func TestTransportConstructorsValidateInputs(t *testing.T) {
	if _, err := NewTransport(nil, uint32(wire.MainNet), true); err == nil {
		t.Fatalf("NewTransport accepted nil connection")
	}

	left, right := net.Pipe()
	defer func() { _ = left.Close() }()
	defer func() { _ = right.Close() }()
	if _, err := NewTransportWithCipher(left, uint32(wire.MainNet), true, nil); err == nil {
		t.Fatalf("NewTransportWithCipher accepted nil cipher")
	}
	cipher, err := bip324_crypto.NewBip324Cipher(uint32(wire.MainNet))
	if err != nil {
		t.Fatalf("NewBip324Cipher err: %s", err)
	}
	if _, err := NewTransportWithCipher(left, uint32(wire.TestNet3), true, cipher); err == nil {
		t.Fatalf("NewTransportWithCipher accepted mismatched network magic")
	}
}

func TestNilTransportMethodsReturnErrors(t *testing.T) {
	var transport *V2Transport
	if err := transport.SendV2Message(wire.NewMsgPing(1)); err == nil {
		t.Fatalf("SendV2Message succeeded on nil transport")
	}
	if err := transport.SendV2MessageBuf(wire.CmdPing, nil); err == nil {
		t.Fatalf("SendV2MessageBuf succeeded on nil transport")
	}
	if _, _, _, err := transport.RecvV2Message(); err == nil {
		t.Fatalf("RecvV2Message succeeded on nil transport")
	}
	if _, err := transport.RecvV2P2pMessage(); err == nil {
		t.Fatalf("RecvV2P2pMessage succeeded on nil transport")
	}
	if _, err := transport.MaybeSendDecoyPackets(); err == nil {
		t.Fatalf("MaybeSendDecoyPackets succeeded on nil transport")
	}
}

func TestEllswiftReceivePrefixMatchesTransportRole(t *testing.T) {
	initiator := &V2Transport{isInitializing: true}
	if err := initiator.recvTheirEllswiftPubKey([]byte{0x01}); err == nil {
		t.Fatalf("initiator accepted a responder-only received prefix")
	}

	responder := &V2Transport{btcNet: uint32(wire.MainNet)}
	tooLong := make([]byte, len(responder.v1Prefix())+1)
	if err := responder.recvTheirEllswiftPubKey(tooLong); err == nil {
		t.Fatalf("responder accepted a prefix longer than the v1 discriminator")
	}
}

func TestTransportDestroyClearsState(t *testing.T) {
	left, right := net.Pipe()
	defer func() { _ = left.Close() }()
	defer func() { _ = right.Close() }()
	cipher, err := bip324_crypto.NewBip324Cipher(uint32(wire.MainNet))
	if err != nil {
		t.Fatalf("NewBip324Cipher err: %s", err)
	}
	transport, err := NewTransportWithCipher(left, uint32(wire.MainNet), true, cipher)
	if err != nil {
		t.Fatalf("NewTransportWithCipher err: %s", err)
	}
	garbageBacking := transport.SendAadAndGarbage
	transport.RecvAad = []byte("received garbage")
	recvBacking := transport.RecvAad

	transport.Destroy()
	if transport.cipher != nil || transport.SendAadAndGarbage != nil || transport.RecvAad != nil {
		t.Fatalf("Destroy retained transport state")
	}
	if !bytes.Equal(garbageBacking, make([]byte, len(garbageBacking))) ||
		!bytes.Equal(recvBacking, make([]byte, len(recvBacking))) {
		t.Fatalf("Destroy did not clear AAD backing memory")
	}
}

func TestGarbageTerminatorBounds(t *testing.T) {
	for _, test := range []struct {
		name      string
		garbage   int
		wantError bool
	}{
		{name: "empty", garbage: 0},
		{name: "maximum", garbage: MaxGarbageLength},
		{name: "too large", garbage: MaxGarbageLength + 1, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			initiatorCipher, _ := initializedCipherPair(t)
			garbage := bytes.Repeat([]byte{0x55}, test.garbage)
			stream := append(append([]byte(nil), garbage...), initiatorCipher.RecvGarbageTerminator...)
			stream = append(stream, 0xaa)
			conn := &chunkedReadConn{data: stream, maxChunk: 7}
			transport := &V2Transport{cipher: initiatorCipher}

			err := transport.lookForGarbage(conn)
			if test.wantError {
				if !errors.Is(err, ErrGarbageTerminator) {
					t.Fatalf("lookForGarbage err = %v, want ErrGarbageTerminator", err)
				}
				wantRemaining := []byte{initiatorCipher.RecvGarbageTerminator[bip324_crypto.GarbageTerminatorLength-1], 0xaa}
				if !bytes.Equal(conn.data, wantRemaining) {
					t.Fatalf("rejected scan left %x, want %x", conn.data, wantRemaining)
				}
				return
			}

			if err != nil {
				t.Fatalf("lookForGarbage err: %s", err)
			}
			if !bytes.Equal(transport.RecvAad, garbage) {
				t.Fatalf("RecvAad length = %d, want %d", len(transport.RecvAad), len(garbage))
			}
			if !bytes.Equal(conn.data, []byte{0xaa}) {
				t.Fatalf("lookForGarbage consumed following bytes: %x remain", conn.data)
			}
		})
	}
}

func TestPacketRoundTripSkipsAuthenticatedDecoy(t *testing.T) {
	initiatorCipher, responderCipher := initializedCipherPair(t)
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	initiator, err := NewTransportWithCipher(clientConn, uint32(wire.MainNet), true, initiatorCipher)
	if err != nil {
		t.Fatalf("NewTransportWithCipher initiator err: %s", err)
	}
	responder, err := NewTransportWithCipher(serverConn, uint32(wire.MainNet), false, responderCipher)
	if err != nil {
		t.Fatalf("NewTransportWithCipher responder err: %s", err)
	}
	garbage := []byte("authenticated garbage")
	initiator.SendAadAndGarbage = append([]byte(nil), garbage...)
	responder.RecvAad = append([]byte(nil), garbage...)

	sendErrors := make(chan error, 1)
	go func() {
		if err := initiator.SendBip324Packet(clientConn, []byte("decoy"), true); err != nil {
			sendErrors <- err
			return
		}
		sendErrors <- initiator.SendBip324Packet(clientConn, []byte("message"), false)
	}()

	got, err := responder.RecvBip324Packet(serverConn)
	if err != nil {
		t.Fatalf("RecvBip324Packet err: %s", err)
	}
	if string(got) != "message" {
		t.Fatalf("RecvBip324Packet = %q, want message", got)
	}
	if err := <-sendErrors; err != nil {
		t.Fatalf("SendBip324Packet err: %s", err)
	}
}

func TestConcurrentPacketSendsRemainFramed(t *testing.T) {
	initiatorCipher, responderCipher := initializedCipherPair(t)
	initiatorConn, responderConn := net.Pipe()
	defer func() { _ = initiatorConn.Close() }()
	defer func() { _ = responderConn.Close() }()

	initiator, err := NewTransportWithCipher(initiatorConn, uint32(wire.MainNet), true, initiatorCipher)
	if err != nil {
		t.Fatalf("NewTransportWithCipher initiator: %s", err)
	}
	responder, err := NewTransportWithCipher(responderConn, uint32(wire.MainNet), false, responderCipher)
	if err != nil {
		t.Fatalf("NewTransportWithCipher responder: %s", err)
	}
	initiator.SendAadAndGarbage = nil
	responder.RecvAad = nil

	const packetCount = 32
	var senders sync.WaitGroup
	senders.Add(packetCount)
	sendErrors := make(chan error, packetCount)
	for id := range packetCount {
		go func() {
			defer senders.Done()
			sendErrors <- initiator.SendBip324Packet(initiatorConn, []byte{byte(id)}, false)
		}()
	}

	seen := make(map[byte]bool, packetCount)
	for range packetCount {
		packet, err := responder.RecvBip324Packet(responderConn)
		if err != nil {
			t.Fatalf("RecvBip324Packet: %s", err)
		}
		if len(packet) != 1 || seen[packet[0]] {
			t.Fatalf("received malformed or duplicate packet %x", packet)
		}
		seen[packet[0]] = true
	}
	senders.Wait()
	close(sendErrors)
	for err := range sendErrors {
		if err != nil {
			t.Fatalf("SendBip324Packet: %s", err)
		}
	}
}

func TestOnlyHighHeaderBitMarksIgnoredPackets(t *testing.T) {
	for header := 0; header <= 0xff; header++ {
		want := header >= int(bip324_crypto.HeaderIgnoreBit)
		if got := packetIsIgnored(byte(header)); got != want {
			t.Fatalf("packetIsIgnored(0x%02x) = %v, want %v", header, got, want)
		}
	}
}

func TestRecvV2P2pMessageDoesNotParsePayload(t *testing.T) {
	initiatorCipher, responderCipher := initializedCipherPair(t)
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()
	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))
	_ = serverConn.SetDeadline(time.Now().Add(5 * time.Second))

	initiator, err := NewTransportWithCipher(clientConn, uint32(wire.MainNet), true, initiatorCipher)
	if err != nil {
		t.Fatalf("NewTransportWithCipher initiator err: %s", err)
	}
	responder, err := NewTransportWithCipher(serverConn, uint32(wire.MainNet), false, responderCipher)
	if err != nil {
		t.Fatalf("NewTransportWithCipher responder err: %s", err)
	}
	initiator.SendAadAndGarbage = nil
	responder.RecvAad = nil

	want := []*P2pMessage{
		{Type: "futuremsg", Payload: []byte{1, 2, 3}},
		{Type: wire.CmdVerAck, Payload: []byte{0xff}},
	}
	sendErrors := make(chan error, 1)
	go func() {
		for _, message := range want {
			if err := initiator.SendV2MessageBuf(message.Type, message.Payload); err != nil {
				sendErrors <- err
				return
			}
		}
		sendErrors <- nil
	}()

	for i, expected := range want {
		got, err := responder.RecvV2P2pMessage()
		if err != nil {
			t.Fatalf("RecvV2P2pMessage %d err: %s", i, err)
		}
		if got.Type != expected.Type || !bytes.Equal(got.Payload, expected.Payload) {
			t.Fatalf("RecvV2P2pMessage %d = %#v, want %#v", i, got, expected)
		}
	}
	if err := <-sendErrors; err != nil {
		t.Fatalf("send raw v2 messages: %s", err)
	}
}

func TestPacketAuthenticationFailure(t *testing.T) {
	initiatorCipher, responderCipher := initializedCipherPair(t)
	packet, err := initiatorCipher.EncryptPacketBuf([]byte("message"), nil, false)
	if err != nil {
		t.Fatalf("EncryptPacketBuf err: %s", err)
	}
	packet[len(packet)-1] ^= 1

	conn := &chunkedReadConn{data: packet, maxChunk: 2}
	transport := &V2Transport{cipher: responderCipher}
	if _, err := transport.RecvBip324Packet(conn); err == nil {
		t.Fatalf("RecvBip324Packet accepted a modified authentication tag")
	}
}

func TestEndToEndV2HandshakeAndMessage(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen err: %s", err)
	}
	defer func() { _ = listener.Close() }()

	type serverResult struct {
		transport *V2Transport
		conn      net.Conn
		err       error
	}
	serverResults := make(chan serverResult, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverResults <- serverResult{err: err}
			return
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		transport, err := NewTransport(conn, uint32(wire.MainNet), false)
		if err == nil {
			transport.SendAadAndGarbage = bytes.Repeat([]byte{0x22}, MaxGarbageLength)
			err = transport.V2Handshake()
		}
		serverResults <- serverResult{transport: transport, conn: conn, err: err}
	}()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial err: %s", err)
	}
	defer func() { _ = clientConn.Close() }()
	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))
	initiator, err := NewTransport(clientConn, uint32(wire.MainNet), true)
	if err != nil {
		t.Fatalf("NewTransport initiator err: %s", err)
	}
	initiator.SendAadAndGarbage = bytes.Repeat([]byte{0x11}, MaxGarbageLength)
	if err := initiator.V2Handshake(); err != nil {
		t.Fatalf("initiator V2Handshake err: %s", err)
	}

	server := <-serverResults
	if server.conn != nil {
		defer func() { _ = server.conn.Close() }()
	}
	if server.err != nil {
		t.Fatalf("responder V2Handshake err: %s", server.err)
	}
	if !bytes.Equal(initiator.SessionID(), server.transport.SessionID()) {
		t.Fatalf("handshake session IDs differ")
	}
	initiatorSession := initiator.SessionID()
	initiatorSession[0] ^= 1
	if bytes.Equal(initiatorSession, initiator.SessionID()) {
		t.Fatalf("SessionID returned mutable transport state")
	}
	if err := initiator.V2Handshake(); err == nil {
		t.Fatalf("V2Handshake succeeded twice")
	}

	if err := initiator.SendV2Message(wire.NewMsgPing(42)); err != nil {
		t.Fatalf("SendV2Message err: %s", err)
	}
	message, command, payload, err := server.transport.RecvV2Message()
	if err != nil {
		t.Fatalf("RecvV2Message err: %s", err)
	}
	if command != wire.CmdPing || len(payload) != 8 {
		t.Fatalf("received command=%q payload=%x", command, payload)
	}
	ping, ok := message.(*wire.MsgPing)
	if !ok || ping.Nonce != 42 {
		t.Fatalf("received message = %#v, want ping nonce 42", message)
	}
}

func TestInteropWithBTCDV2Transport(t *testing.T) {
	t.Run("local initiator", func(t *testing.T) {
		localConn, btcdConn := tcpConnPair(t)
		defer func() { _ = localConn.Close() }()
		defer func() { _ = btcdConn.Close() }()
		_ = localConn.SetDeadline(time.Now().Add(5 * time.Second))
		_ = btcdConn.SetDeadline(time.Now().Add(5 * time.Second))

		wantFromLocal, err := EncodeBufAsV2("futuremsg", []byte{1, 2, 3})
		if err != nil {
			t.Fatalf("EncodeBufAsV2 local message err: %s", err)
		}
		wantFromBTCD, err := EncodeBufAsV2(wire.CmdPing, make([]byte, 8))
		if err != nil {
			t.Fatalf("EncodeBufAsV2 btcd message err: %s", err)
		}

		type result struct {
			received []byte
			err      error
		}
		results := make(chan result, 1)
		go func() {
			peer := btcdv2.NewPeer()
			peer.UseReadWriter(btcdConn)
			if err := peer.RespondV2Handshake(17, btcdv2.BitcoinNet(wire.MainNet)); err != nil {
				results <- result{err: fmt.Errorf("RespondV2Handshake: %w", err)}
				return
			}
			if err := peer.CompleteHandshake(false, []int{0, 7, 249}, btcdv2.BitcoinNet(wire.MainNet)); err != nil {
				results <- result{err: fmt.Errorf("CompleteHandshake: %w", err)}
				return
			}
			received, err := peer.V2ReceivePacket(nil)
			if err != nil {
				results <- result{err: fmt.Errorf("V2ReceivePacket: %w", err)}
				return
			}
			if _, _, err := peer.V2EncPacket(wantFromBTCD, nil, false); err != nil {
				results <- result{err: fmt.Errorf("V2EncPacket: %w", err)}
				return
			}
			results <- result{received: received}
		}()

		local, err := NewTransport(localConn, uint32(wire.MainNet), true)
		if err != nil {
			t.Fatalf("NewTransport err: %s", err)
		}
		if err := local.V2Handshake(); err != nil {
			t.Fatalf("local V2Handshake err: %s", err)
		}
		if err := local.SendBip324Packet(localConn, wantFromLocal, false); err != nil {
			t.Fatalf("local SendBip324Packet err: %s", err)
		}
		gotFromBTCD, err := local.RecvBip324Packet(localConn)
		if err != nil {
			t.Fatalf("local RecvBip324Packet err: %s", err)
		}
		if !bytes.Equal(gotFromBTCD, wantFromBTCD) {
			t.Fatalf("local received %x, want %x", gotFromBTCD, wantFromBTCD)
		}

		select {
		case result := <-results:
			if result.err != nil {
				t.Fatalf("btcd responder: %s", result.err)
			}
			if !bytes.Equal(result.received, wantFromLocal) {
				t.Fatalf("btcd received %x, want %x", result.received, wantFromLocal)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("btcd responder did not finish")
		}
	})

	t.Run("local responder", func(t *testing.T) {
		btcdConn, localConn := tcpConnPair(t)
		defer func() { _ = localConn.Close() }()
		defer func() { _ = btcdConn.Close() }()
		_ = localConn.SetDeadline(time.Now().Add(5 * time.Second))
		_ = btcdConn.SetDeadline(time.Now().Add(5 * time.Second))

		wantFromBTCD, err := EncodeBufAsV2("futuremsg", []byte{4, 5, 6})
		if err != nil {
			t.Fatalf("EncodeBufAsV2 btcd message err: %s", err)
		}
		wantFromLocal, err := EncodeBufAsV2(wire.CmdPong, make([]byte, 8))
		if err != nil {
			t.Fatalf("EncodeBufAsV2 local message err: %s", err)
		}

		type result struct {
			received []byte
			err      error
		}
		results := make(chan result, 1)
		go func() {
			peer := btcdv2.NewPeer()
			peer.UseReadWriter(btcdConn)
			if err := peer.InitiateV2Handshake(23); err != nil {
				results <- result{err: fmt.Errorf("InitiateV2Handshake: %w", err)}
				return
			}
			if err := peer.CompleteHandshake(true, []int{0, 7, 249}, btcdv2.BitcoinNet(wire.MainNet)); err != nil {
				results <- result{err: fmt.Errorf("CompleteHandshake: %w", err)}
				return
			}
			if _, _, err := peer.V2EncPacket(wantFromBTCD, nil, false); err != nil {
				results <- result{err: fmt.Errorf("V2EncPacket: %w", err)}
				return
			}
			received, err := peer.V2ReceivePacket(nil)
			if err != nil {
				results <- result{err: fmt.Errorf("V2ReceivePacket: %w", err)}
				return
			}
			results <- result{received: received}
		}()

		local, err := NewTransport(localConn, uint32(wire.MainNet), false)
		if err != nil {
			t.Fatalf("NewTransport err: %s", err)
		}
		if err := local.V2Handshake(); err != nil {
			t.Fatalf("local V2Handshake err: %s", err)
		}
		gotFromBTCD, err := local.RecvBip324Packet(localConn)
		if err != nil {
			t.Fatalf("local RecvBip324Packet err: %s", err)
		}
		if !bytes.Equal(gotFromBTCD, wantFromBTCD) {
			t.Fatalf("local received %x, want %x", gotFromBTCD, wantFromBTCD)
		}
		if err := local.SendBip324Packet(localConn, wantFromLocal, false); err != nil {
			t.Fatalf("local SendBip324Packet err: %s", err)
		}

		select {
		case result := <-results:
			if result.err != nil {
				t.Fatalf("btcd initiator: %s", result.err)
			}
			if !bytes.Equal(result.received, wantFromLocal) {
				t.Fatalf("btcd received %x, want %x", result.received, wantFromLocal)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("btcd initiator did not finish")
		}
	})
}

func TestNetworkHelpersRejectInvalidConnections(t *testing.T) {
	if err := WriteData(nil, []byte{1}); err == nil {
		t.Fatalf("WriteData accepted nil connection")
	}
	if _, err := ReadData(nil, 1); err == nil {
		t.Fatalf("ReadData accepted nil connection")
	}
	if err := WriteData(&zeroWriteConn{}, []byte{1}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("WriteData zero write err = %v, want io.ErrShortWrite", err)
	}
}

func TestRandomHelpersRejectInvalidBounds(t *testing.T) {
	for _, max := range []int{0, -1} {
		if _, err := randomInt(max); err == nil {
			t.Fatalf("randomInt(%d) succeeded", max)
		}
	}
	if _, err := randomBytesUpTo(-1); err == nil {
		t.Fatalf("randomBytesUpTo accepted a negative maximum")
	}
}

func v1PrefixForNet(btcNet uint32) []byte {
	var magic [4]byte
	binary.LittleEndian.PutUint32(magic[:], btcNet)

	prefix := make([]byte, 0, 16)
	prefix = append(prefix, magic[:]...)
	prefix = append(prefix, v1VersionMsgCommand...)
	return prefix
}

func tcpConnPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for TCP pair: %s", err)
	}
	defer func() { _ = listener.Close() }()

	type acceptResult struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, err := listener.Accept()
		accepted <- acceptResult{conn: conn, err: err}
	}()

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial TCP pair: %s", err)
	}
	result := <-accepted
	if result.err != nil {
		_ = client.Close()
		t.Fatalf("accept TCP pair: %s", result.err)
	}
	return client, result.conn
}

func initializedCipherPair(t *testing.T) (*bip324_crypto.Bip324Cipher, *bip324_crypto.Bip324Cipher) {
	t.Helper()

	initiatorCipher, err := bip324_crypto.NewBip324Cipher(uint32(wire.MainNet))
	if err != nil {
		t.Fatalf("NewBip324Cipher initiator err: %s", err)
	}
	responderCipher, err := bip324_crypto.NewBip324Cipher(uint32(wire.MainNet))
	if err != nil {
		t.Fatalf("NewBip324Cipher responder err: %s", err)
	}

	if err := initiatorCipher.Init(responderCipher.GetOurEllswiftPublicKey(), true); err != nil {
		t.Fatalf("initiator Init err: %s", err)
	}
	if err := responderCipher.Init(initiatorCipher.GetOurEllswiftPublicKey(), false); err != nil {
		t.Fatalf("responder Init err: %s", err)
	}

	return initiatorCipher, responderCipher
}

type chunkedReadConn struct {
	data     []byte
	maxChunk int
}

func (c *chunkedReadConn) Read(b []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}

	n := len(c.data)
	if n > c.maxChunk {
		n = c.maxChunk
	}
	if n > len(b) {
		n = len(b)
	}

	copy(b, c.data[:n])
	c.data = c.data[n:]
	return n, nil
}

func (c *chunkedReadConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (c *chunkedReadConn) Close() error {
	return nil
}

func (c *chunkedReadConn) LocalAddr() net.Addr {
	return dummyAddr("local")
}

func (c *chunkedReadConn) RemoteAddr() net.Addr {
	return dummyAddr("remote")
}

func (c *chunkedReadConn) SetDeadline(time.Time) error {
	return nil
}

func (c *chunkedReadConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *chunkedReadConn) SetWriteDeadline(time.Time) error {
	return nil
}

type dummyAddr string

func (a dummyAddr) Network() string {
	return string(a)
}

func (a dummyAddr) String() string {
	return string(a)
}

type zeroWriteConn struct {
	chunkedReadConn
}

func (c *zeroWriteConn) Write([]byte) (int, error) {
	return 0, nil
}

func FuzzDecodeV2MessageType(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{shortMsgCmdCodes[wire.CmdPing], 1, 2, 3})
	longPing, err := EncodeBufAsV2(wire.CmdVersion, []byte{4, 5, 6})
	if err != nil {
		f.Fatalf("seed long message: %s", err)
	}
	f.Add(longPing)
	f.Add([]byte{0, 'p', 'i', 0, 'g'})
	f.Add([]byte{0xff})

	f.Fuzz(func(t *testing.T, encoded []byte) {
		command, payload, err := decodeV2MessageType(encoded)
		if err != nil {
			return
		}
		if err := validateCommand(command); err != nil {
			t.Fatalf("decoder returned invalid command %q: %s", command, err)
		}
		canonical, err := EncodeBufAsV2(command, payload)
		if err != nil {
			t.Fatalf("re-encode decoded message: %s", err)
		}
		gotCommand, gotPayload, err := decodeV2MessageType(canonical)
		if err != nil {
			t.Fatalf("decode canonical message: %s", err)
		}
		if gotCommand != command || !bytes.Equal(gotPayload, payload) {
			t.Fatalf("canonical round trip changed (%q, %x) to (%q, %x)", command, payload, gotCommand, gotPayload)
		}
	})
}

func FuzzDecodeCommand(f *testing.F) {
	valid := make([]byte, wire.CommandSize)
	copy(valid, wire.CmdVersion)
	f.Add(valid)
	f.Add(make([]byte, wire.CommandSize))
	f.Add([]byte{'p', 'i', 0, 'g'})
	f.Add([]byte("twelve-bytes"))

	f.Fuzz(func(t *testing.T, field []byte) {
		command, err := DecodeCommand(field)
		if err != nil {
			return
		}
		if err := validateCommand(command); err != nil {
			t.Fatalf("DecodeCommand returned invalid command %q: %s", command, err)
		}
		canonical := make([]byte, wire.CommandSize)
		copy(canonical, command)
		got, err := DecodeCommand(canonical)
		if err != nil || got != command {
			t.Fatalf("canonical DecodeCommand = %q, %v; want %q", got, err, command)
		}
	})
}
