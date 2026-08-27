package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	bip324_transport "github.com/lnliz/bitcoin-bip324-proxy/transport"

	"github.com/btcsuite/btcd/wire"
	"github.com/rs/zerolog"
)

const proxyTestTimeout = 10 * time.Second

func TestMain(m *testing.M) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	os.Exit(m.Run())
}

func getVersionMsg() *wire.MsgVersion {
	you := wire.NewNetAddress(&net.TCPAddr{IP: net.ParseIP("192.168.0.1"), Port: 8333}, wire.SFNodeNetwork)
	you.Timestamp = time.Time{}
	me := wire.NewNetAddress(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8333}, wire.SFNodeNetwork)
	me.Timestamp = time.Time{}
	return wire.NewMsgVersion(me, you, 876543, 1234)
}

type v2PeerResult struct {
	commands  []string
	userAgent string
	err       error
}

func runV2Peer(conn net.Conn) v2PeerResult {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(proxyTestTimeout))

	transport, err := bip324_transport.NewTransport(conn, uint32(wire.MainNet), false)
	if err != nil {
		return v2PeerResult{err: fmt.Errorf("new responder transport: %w", err)}
	}
	if err := transport.V2Handshake(); err != nil {
		return v2PeerResult{err: fmt.Errorf("responder handshake: %w", err)}
	}

	if err := transport.SendV2Message(getVersionMsg()); err != nil {
		return v2PeerResult{err: fmt.Errorf("send version: %w", err)}
	}

	versionMessage, command, _, err := transport.RecvV2Message()
	if err != nil {
		return v2PeerResult{err: fmt.Errorf("receive version: %w", err)}
	}
	version, ok := versionMessage.(*wire.MsgVersion)
	if !ok {
		return v2PeerResult{err: fmt.Errorf("received %T, want *wire.MsgVersion", versionMessage)}
	}
	result := v2PeerResult{
		commands:  []string{command},
		userAgent: version.UserAgent,
	}

	if err := transport.SendV2Message(wire.NewMsgVerAck()); err != nil {
		result.err = fmt.Errorf("send verack: %w", err)
		return result
	}

	pingMessage, command, _, err := transport.RecvV2Message()
	if err != nil {
		result.err = fmt.Errorf("receive ping: %w", err)
		return result
	}
	ping, ok := pingMessage.(*wire.MsgPing)
	if !ok || ping.Nonce != 123 {
		result.err = fmt.Errorf("received ping %#v, want nonce 123", pingMessage)
		return result
	}
	result.commands = append(result.commands, command)

	if err := transport.SendV2Message(wire.NewMsgPong(321)); err != nil {
		result.err = fmt.Errorf("send pong: %w", err)
	}
	return result
}

func TestProxyRelaysV1ToV2(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %s", err)
	}
	defer func() { _ = listener.Close() }()

	peerResults := make(chan v2PeerResult, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			peerResults <- v2PeerResult{err: fmt.Errorf("accept: %w", err)}
			return
		}
		peerResults <- runV2Peer(conn)
	}()

	proxySide, clientSide := net.Pipe()
	defer func() { _ = clientSide.Close() }()
	_ = clientSide.SetDeadline(time.Now().Add(proxyTestTimeout))

	handler := NewConnectionHandler(
		wire.MainNet, listener.Addr().String(), proxySide,
		false, true, false, true,
	)
	handlerDone := make(chan struct{})
	go func() {
		handler.handleLocalConnection()
		close(handlerDone)
	}()

	client := NewConnectionHandler(wire.MainNet, "", nil, false, false, false, false)
	if err := client.SendV1Message(clientSide, getVersionMsg()); err != nil {
		t.Fatalf("send local version: %s", err)
	}

	message, _, _, err := client.RecvV1Message(clientSide)
	if err != nil {
		t.Fatalf("receive remote version: %s", err)
	}
	if _, ok := message.(*wire.MsgVersion); !ok {
		t.Fatalf("received %T, want *wire.MsgVersion", message)
	}

	message, _, _, err = client.RecvV1Message(clientSide)
	if err != nil {
		t.Fatalf("receive verack: %s", err)
	}
	if _, ok := message.(*wire.MsgVerAck); !ok {
		t.Fatalf("received %T, want *wire.MsgVerAck", message)
	}

	if err := client.SendV1Message(clientSide, wire.NewMsgPing(123)); err != nil {
		t.Fatalf("send ping: %s", err)
	}
	message, _, _, err = client.RecvV1Message(clientSide)
	if err != nil {
		t.Fatalf("receive pong: %s", err)
	}
	pong, ok := message.(*wire.MsgPong)
	if !ok || pong.Nonce != 321 {
		t.Fatalf("received pong %#v, want nonce 321", message)
	}

	var result v2PeerResult
	select {
	case result = <-peerResults:
	case <-time.After(proxyTestTimeout):
		t.Fatalf("v2 peer did not finish")
	}
	if result.err != nil {
		t.Fatalf("v2 peer: %s", result.err)
	}
	if got, want := result.commands, []string{wire.CmdVersion, wire.CmdPing}; !equalStrings(got, want) {
		t.Fatalf("v2 peer commands = %v, want %v", got, want)
	}
	if !strings.Contains(result.userAgent, proxyUserAgentName+":"+proxyUserAgentVersion+"/") {
		t.Fatalf("proxied user agent %q does not contain proxy identifier", result.userAgent)
	}

	_ = clientSide.Close()
	select {
	case <-handlerDone:
	case <-time.After(proxyTestTimeout):
		t.Fatalf("proxy handler did not stop")
	}
	if handler.transport != nil {
		t.Fatalf("completed proxy handler retained v2 transport key state")
	}
}

func TestV2FailureFallsBackAndSendsVersionOnce(t *testing.T) {
	firstProxy, firstPeer := net.Pipe()
	_ = firstPeer.Close()
	secondProxy, secondPeer := net.Pipe()
	defer func() { _ = secondPeer.Close() }()

	proxySide, clientSide := net.Pipe()
	defer func() { _ = clientSide.Close() }()
	_ = clientSide.SetDeadline(time.Now().Add(proxyTestTimeout))

	handler := NewConnectionHandler(wire.MainNet, "unused", proxySide, false, false, false, false)
	var dialCount atomic.Int32
	handler.dialRemote = func(string) (net.Conn, error) {
		switch dialCount.Add(1) {
		case 1:
			return firstProxy, nil
		case 2:
			return secondProxy, nil
		default:
			return nil, fmt.Errorf("unexpected extra dial")
		}
	}

	type fallbackResult struct {
		command string
		err     error
	}
	peerResult := make(chan fallbackResult, 1)
	go func() {
		message, _, err := wire.ReadMessage(secondPeer, wire.ProtocolVersion, wire.MainNet)
		if err != nil {
			peerResult <- fallbackResult{err: fmt.Errorf("read fallback version: %w", err)}
			return
		}

		if err := secondPeer.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			peerResult <- fallbackResult{err: err}
			return
		}
		var oneByte [1]byte
		n, err := secondPeer.Read(oneByte[:])
		if err == nil || n != 0 {
			peerResult <- fallbackResult{err: fmt.Errorf("received an extra byte after version: n=%d err=%v", n, err)}
			return
		}
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			peerResult <- fallbackResult{err: fmt.Errorf("waiting for duplicate version: %w", err)}
			return
		}
		peerResult <- fallbackResult{command: message.Command()}
	}()

	handlerDone := make(chan struct{})
	go func() {
		handler.handleLocalConnection()
		close(handlerDone)
	}()

	client := NewConnectionHandler(wire.MainNet, "", nil, false, false, false, false)
	if err := client.SendV1Message(clientSide, getVersionMsg()); err != nil {
		t.Fatalf("send local version: %s", err)
	}
	var result fallbackResult
	select {
	case result = <-peerResult:
	case <-time.After(proxyTestTimeout):
		t.Fatalf("fallback peer did not receive a version message")
	}
	if result.err != nil {
		t.Fatalf("fallback peer: %s", result.err)
	}
	if result.command != wire.CmdVersion {
		t.Fatalf("fallback command = %q, want version", result.command)
	}
	if got := dialCount.Load(); got != 2 {
		t.Fatalf("dial count = %d, want 2", got)
	}
	if handler.transport != nil {
		t.Fatalf("failed v2 transport was retained during v1 fallback")
	}

	_ = secondPeer.Close()
	_ = clientSide.Close()
	select {
	case <-handlerDone:
	case <-time.After(proxyTestTimeout):
		t.Fatalf("fallback proxy handler did not stop")
	}
}

func TestV1ProxyPreservesInitialVersionPayload(t *testing.T) {
	proxyRemote, peerSide := net.Pipe()
	defer func() { _ = peerSide.Close() }()
	proxyLocal, clientSide := net.Pipe()
	defer func() { _ = clientSide.Close() }()
	_ = peerSide.SetDeadline(time.Now().Add(proxyTestTimeout))
	_ = clientSide.SetDeadline(time.Now().Add(proxyTestTimeout))

	handler := NewConnectionHandler(wire.MainNet, "unused", proxyLocal, true, false, false, false)
	handler.dialRemote = func(string) (net.Conn, error) {
		return proxyRemote, nil
	}
	handlerDone := make(chan struct{})
	go func() {
		handler.handleLocalConnection()
		close(handlerDone)
	}()

	versionPayload := encodeWirePayload(t, getVersionMsg())
	if len(versionPayload) == 0 {
		t.Fatalf("encoded version payload is empty")
	}
	// The relay flag is optional in a version payload. A transparent proxy must
	// not add it merely because its decoder represents the absent value.
	versionPayload = versionPayload[:len(versionPayload)-1]

	type peerResult struct {
		message *bip324_transport.P2pMessage
		err     error
	}
	peerResults := make(chan peerResult, 1)
	go func() {
		framer := NewConnectionHandler(wire.MainNet, "", nil, false, false, false, false)
		message, err := framer.recvV1P2pMessage(peerSide)
		peerResults <- peerResult{message: message, err: err}
	}()

	client := NewConnectionHandler(wire.MainNet, "", nil, false, false, false, false)
	initial := &bip324_transport.P2pMessage{Type: wire.CmdVersion, Payload: versionPayload}
	if err := client.SendV1MessageBytes(clientSide, initial); err != nil {
		t.Fatalf("send local version: %s", err)
	}

	select {
	case result := <-peerResults:
		if result.err != nil {
			t.Fatalf("receive proxied version: %s", result.err)
		}
		if result.message.Type != wire.CmdVersion || !bytes.Equal(result.message.Payload, versionPayload) {
			t.Fatalf("proxied initial message = %#v, want exact version payload", result.message)
		}
	case <-time.After(proxyTestTimeout):
		t.Fatalf("peer did not receive initial version")
	}

	_ = clientSide.Close()
	_ = peerSide.Close()
	select {
	case <-handlerDone:
	case <-time.After(proxyTestTimeout):
		t.Fatalf("proxy handler did not stop")
	}
}

func TestFallbackReconnectFailureDoesNotPanic(t *testing.T) {
	firstProxy, firstPeer := net.Pipe()
	_ = firstPeer.Close()
	proxySide, clientSide := net.Pipe()
	defer func() { _ = clientSide.Close() }()

	handler := NewConnectionHandler(wire.MainNet, "unused", proxySide, false, false, false, false)
	var dialCount atomic.Int32
	handler.dialRemote = func(string) (net.Conn, error) {
		if dialCount.Add(1) == 1 {
			return firstProxy, nil
		}
		return nil, errors.New("reconnect failed")
	}

	panicResult := make(chan any, 1)
	go func() {
		defer func() {
			panicResult <- recover()
		}()
		handler.handleLocalConnection()
	}()

	client := NewConnectionHandler(wire.MainNet, "", nil, false, false, false, false)
	if err := client.SendV1Message(clientSide, getVersionMsg()); err != nil {
		t.Fatalf("send local version: %s", err)
	}
	select {
	case panicValue := <-panicResult:
		if panicValue != nil {
			t.Fatalf("handler panicked after reconnect failure: %v", panicValue)
		}
	case <-time.After(proxyTestTimeout):
		t.Fatalf("handler did not return after reconnect failure")
	}
	if got := dialCount.Load(); got != 2 {
		t.Fatalf("dial count = %d, want 2", got)
	}
}

func TestV1ProxyRelaysRawApplicationMessages(t *testing.T) {
	proxyRemote, peerSide := net.Pipe()
	defer func() { _ = peerSide.Close() }()
	proxyLocal, clientSide := net.Pipe()
	defer func() { _ = clientSide.Close() }()
	_ = peerSide.SetDeadline(time.Now().Add(proxyTestTimeout))
	_ = clientSide.SetDeadline(time.Now().Add(proxyTestTimeout))

	handler := NewConnectionHandler(wire.MainNet, "unused", proxyLocal, true, false, false, false)
	handler.dialRemote = func(string) (net.Conn, error) {
		return proxyRemote, nil
	}
	handlerDone := make(chan struct{})
	go func() {
		handler.handleLocalConnection()
		close(handlerDone)
	}()

	peerResult := make(chan *bip324_transport.P2pMessage, 1)
	peerErrors := make(chan error, 1)
	go func() {
		if message, _, err := wire.ReadMessage(peerSide, wire.ProtocolVersion, wire.MainNet); err != nil {
			peerErrors <- fmt.Errorf("read initial version: %w", err)
			return
		} else if message.Command() != wire.CmdVersion {
			peerErrors <- fmt.Errorf("initial command = %q", message.Command())
			return
		}

		framer := NewConnectionHandler(wire.MainNet, "", nil, false, false, false, false)
		future := &bip324_transport.P2pMessage{Type: "futuremsg", Payload: []byte{1, 2, 3}}
		if err := framer.SendV1MessageBytes(peerSide, future); err != nil {
			peerErrors <- fmt.Errorf("send future message: %w", err)
			return
		}

		message, err := framer.recvV1P2pMessage(peerSide)
		if err != nil {
			peerErrors <- fmt.Errorf("receive malformed known message: %w", err)
			return
		}
		peerResult <- message
	}()

	client := NewConnectionHandler(wire.MainNet, "", nil, false, false, false, false)
	if err := client.SendV1Message(clientSide, getVersionMsg()); err != nil {
		t.Fatalf("send local version: %s", err)
	}
	future, err := client.recvV1P2pMessage(clientSide)
	if err != nil {
		t.Fatalf("receive future message: %s", err)
	}
	if future.Type != "futuremsg" || !bytes.Equal(future.Payload, []byte{1, 2, 3}) {
		t.Fatalf("future message = %#v", future)
	}

	malformedKnown := &bip324_transport.P2pMessage{Type: wire.CmdVerAck, Payload: []byte{0x01}}
	if err := client.SendV1MessageBytes(clientSide, malformedKnown); err != nil {
		t.Fatalf("send malformed known message: %s", err)
	}

	select {
	case err := <-peerErrors:
		t.Fatalf("v1 peer: %s", err)
	case received := <-peerResult:
		if received.Type != wire.CmdVerAck || !bytes.Equal(received.Payload, malformedKnown.Payload) {
			t.Fatalf("relayed message = %#v, want %#v", received, malformedKnown)
		}
	case <-time.After(proxyTestTimeout):
		t.Fatalf("v1 peer did not receive relayed message")
	}

	_ = clientSide.Close()
	_ = peerSide.Close()
	select {
	case <-handlerDone:
	case <-time.After(proxyTestTimeout):
		t.Fatalf("v1 proxy handler did not stop")
	}
}

func TestV2ProxyRelaysRawApplicationMessages(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %s", err)
	}
	defer func() { _ = listener.Close() }()

	type peerResult struct {
		initial  *bip324_transport.P2pMessage
		received []*bip324_transport.P2pMessage
		err      error
	}
	peerResults := make(chan peerResult, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			peerResults <- peerResult{err: fmt.Errorf("accept: %w", err)}
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(proxyTestTimeout))

		transport, err := bip324_transport.NewTransport(conn, uint32(wire.MainNet), false)
		if err != nil {
			peerResults <- peerResult{err: fmt.Errorf("new transport: %w", err)}
			return
		}
		defer transport.Destroy()
		if err := transport.V2Handshake(); err != nil {
			peerResults <- peerResult{err: fmt.Errorf("v2 handshake: %w", err)}
			return
		}
		if err := transport.SendV2Message(getVersionMsg()); err != nil {
			peerResults <- peerResult{err: fmt.Errorf("send remote version: %w", err)}
			return
		}

		initial, err := transport.RecvV2P2pMessage()
		if err != nil {
			peerResults <- peerResult{err: fmt.Errorf("receive initial version: %w", err)}
			return
		}

		var received []*bip324_transport.P2pMessage
		for range 2 {
			message, err := transport.RecvV2P2pMessage()
			if err != nil {
				peerResults <- peerResult{err: fmt.Errorf("receive raw message: %w", err)}
				return
			}
			received = append(received, message)
		}

		for _, message := range []*bip324_transport.P2pMessage{
			{Type: "futuremsg", Payload: []byte{9, 8, 7}},
			{Type: wire.CmdVerAck, Payload: []byte{0xff}},
		} {
			if err := transport.SendV2MessageBuf(message.Type, message.Payload); err != nil {
				peerResults <- peerResult{err: fmt.Errorf("send raw message: %w", err)}
				return
			}
		}
		peerResults <- peerResult{initial: initial, received: received}
	}()

	proxySide, clientSide := net.Pipe()
	defer func() { _ = clientSide.Close() }()
	_ = clientSide.SetDeadline(time.Now().Add(proxyTestTimeout))
	handler := NewConnectionHandler(
		wire.MainNet, listener.Addr().String(), proxySide,
		false, true, false, false,
	)
	handlerDone := make(chan struct{})
	go func() {
		handler.handleLocalConnection()
		close(handlerDone)
	}()

	client := NewConnectionHandler(wire.MainNet, "", nil, false, false, false, false)
	initialPayload := encodeWirePayload(t, getVersionMsg())
	initialPayload = initialPayload[:len(initialPayload)-1]
	if err := client.SendV1MessageBytes(clientSide, &bip324_transport.P2pMessage{
		Type: wire.CmdVersion, Payload: initialPayload,
	}); err != nil {
		t.Fatalf("send initial version: %s", err)
	}
	remoteVersion, err := client.recvV1P2pMessage(clientSide)
	if err != nil || remoteVersion.Type != wire.CmdVersion {
		t.Fatalf("receive remote version: message=%#v err=%v", remoteVersion, err)
	}

	localMessages := []*bip324_transport.P2pMessage{
		{Type: "futuremsg", Payload: []byte{1, 2, 3}},
		{Type: wire.CmdVerAck, Payload: []byte{0x01}},
	}
	for _, message := range localMessages {
		if err := client.SendV1MessageBytes(clientSide, message); err != nil {
			t.Fatalf("send raw local message: %s", err)
		}
	}

	remoteMessages := []*bip324_transport.P2pMessage{
		{Type: "futuremsg", Payload: []byte{9, 8, 7}},
		{Type: wire.CmdVerAck, Payload: []byte{0xff}},
	}
	for _, expected := range remoteMessages {
		message, err := client.recvV1P2pMessage(clientSide)
		if err != nil {
			t.Fatalf("receive raw remote message: %s", err)
		}
		if message.Type != expected.Type || !bytes.Equal(message.Payload, expected.Payload) {
			t.Fatalf("remote message = %#v, want %#v", message, expected)
		}
	}

	select {
	case result := <-peerResults:
		if result.err != nil {
			t.Fatalf("v2 peer: %s", result.err)
		}
		if result.initial.Type != wire.CmdVersion || !bytes.Equal(result.initial.Payload, initialPayload) {
			t.Fatalf("initial v2 message = %#v, want exact payload", result.initial)
		}
		for i, expected := range localMessages {
			message := result.received[i]
			if message.Type != expected.Type || !bytes.Equal(message.Payload, expected.Payload) {
				t.Fatalf("local message %d = %#v, want %#v", i, message, expected)
			}
		}
	case <-time.After(proxyTestTimeout):
		t.Fatalf("v2 peer did not finish")
	}

	_ = clientSide.Close()
	select {
	case <-handlerDone:
	case <-time.After(proxyTestTimeout):
		t.Fatalf("v2 proxy handler did not stop")
	}
}

func TestV1HeaderValidationDoesNotReadPayload(t *testing.T) {
	handler := NewConnectionHandler(wire.MainNet, "", nil, false, false, false, false)

	tests := []struct {
		name   string
		header []byte
		want   string
	}{
		{name: "short", header: make([]byte, v1HeaderLength-1), want: "header length"},
		{name: "oversized", header: makeV1Header(wire.CmdPing, wire.MaxMessagePayload+1), want: "too large"},
		{name: "malformed padding", header: makeMalformedCommandHeader(), want: "invalid v1 command"},
		{name: "wrong network", header: makeWrongNetworkHeader(), want: "net magic"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := &readSpyConn{}
			_, err := handler.recvV1P2pMessageWithHeader(test.header, conn)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
			if conn.readCalled {
				t.Fatalf("invalid header caused a payload read")
			}
		})
	}
}

func TestInitialVersionHeaderValidationDoesNotReadPayload(t *testing.T) {
	handler := NewConnectionHandler(wire.MainNet, "", nil, false, false, false, false)
	maxVersionPayload := (&wire.MsgVersion{}).MaxPayloadLength(wire.ProtocolVersion)

	for _, test := range []struct {
		name   string
		header []byte
	}{
		{name: "non-version", header: makeV1Header(wire.CmdPing, 0)},
		{name: "oversized-version", header: makeV1Header(wire.CmdVersion, maxVersionPayload+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn := &readSpyConn{}
			if _, _, _, err := handler.RecvV1MessageWithHeader(test.header, conn); err == nil {
				t.Fatalf("RecvV1MessageWithHeader accepted %s", test.name)
			}
			if conn.readCalled {
				t.Fatalf("invalid initial header caused a payload read")
			}
		})
	}
}

func TestInitialVersionPreservesUnknownTrailingFields(t *testing.T) {
	handler := NewConnectionHandler(wire.MainNet, "", nil, false, false, false, false)
	payload := encodeWirePayload(t, getVersionMsg())
	payload = append(payload, 0xaa, 0xbb)
	encoded, err := bip324_transport.EncodeV1Message(wire.CmdVersion, payload)
	if err != nil {
		t.Fatalf("EncodeV1Message: %s", err)
	}
	header := append(mainnetMagic(), encoded[:wire.CommandSize+8]...)

	reader, writer := net.Pipe()
	defer func() { _ = reader.Close() }()
	go func() {
		_ = bip324_transport.WriteData(writer, payload)
		_ = writer.Close()
	}()

	message, command, gotPayload, err := handler.RecvV1MessageWithHeader(header, reader)
	if err != nil {
		t.Fatalf("RecvV1MessageWithHeader: %s", err)
	}
	if _, ok := message.(*wire.MsgVersion); !ok || command != wire.CmdVersion {
		t.Fatalf("decoded initial message = %T, %q", message, command)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("initial version payload changed: got %x, want %x", gotPayload, payload)
	}
}

func TestInitialDeadlineFailurePreventsReadAndDial(t *testing.T) {
	conn := &readSpyConn{readDeadlineErr: errors.New("deadlines unsupported")}
	handler := NewConnectionHandler(wire.MainNet, "unused", conn, false, false, false, false)
	var dialCount atomic.Int32
	handler.dialRemote = func(string) (net.Conn, error) {
		dialCount.Add(1)
		return nil, errors.New("must not dial")
	}

	handler.handleLocalConnection()
	if conn.readCalled {
		t.Fatalf("handler read without an initial-version deadline")
	}
	if got := dialCount.Load(); got != 0 {
		t.Fatalf("dial count = %d, want 0", got)
	}
}

func TestV1ChecksumValidation(t *testing.T) {
	handler := NewConnectionHandler(wire.MainNet, "", nil, false, false, false, false)
	payload := []byte{1, 2, 3}
	encoded, err := bip324_transport.EncodeV1Message(wire.CmdPing, payload)
	if err != nil {
		t.Fatalf("encode v1 message: %s", err)
	}
	header := append(mainnetMagic(), encoded[:wire.CommandSize+8]...)
	header[20] ^= 1

	reader, writer := net.Pipe()
	defer func() { _ = reader.Close() }()
	go func() {
		_ = bip324_transport.WriteData(writer, payload)
		_ = writer.Close()
	}()

	if _, err := handler.recvV1P2pMessageWithHeader(header, reader); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("checksum error = %v", err)
	}
}

func TestOversizedProxyUserAgentPreventsDial(t *testing.T) {
	proxySide, clientSide := net.Pipe()
	defer func() { _ = clientSide.Close() }()
	handler := NewConnectionHandler(wire.MainNet, "unused", proxySide, true, false, false, true)
	var dialCount atomic.Int32
	handler.dialRemote = func(string) (net.Conn, error) {
		dialCount.Add(1)
		return nil, errors.New("must not dial")
	}

	done := make(chan struct{})
	go func() {
		handler.handleLocalConnection()
		close(done)
	}()
	version := getVersionMsg()
	version.UserAgent = strings.Repeat("a", wire.MaxUserAgentLen)
	client := NewConnectionHandler(wire.MainNet, "", nil, false, false, false, false)
	if err := client.SendV1Message(clientSide, version); err != nil {
		t.Fatalf("send version: %s", err)
	}

	select {
	case <-done:
	case <-time.After(proxyTestTimeout):
		t.Fatalf("handler did not reject oversized appended user agent")
	}
	if got := dialCount.Load(); got != 0 {
		t.Fatalf("dial count = %d, want 0", got)
	}
}

func TestMetricCommandLabelIsBounded(t *testing.T) {
	if got := metricCommandLabel(wire.CmdPing); got != wire.CmdPing {
		t.Fatalf("metricCommandLabel(ping) = %q", got)
	}
	if got := metricCommandLabel("futuremsg"); got != "other" {
		t.Fatalf("metricCommandLabel(futuremsg) = %q, want other", got)
	}
}

func TestParsePeers(t *testing.T) {
	got := parsePeers(" 127.0.0.1:8333, , [::1]:8333 ,,example.test:8333 ")
	want := []string{"127.0.0.1:8333", "[::1]:8333", "example.test:8333"}
	if !equalStrings(got, want) {
		t.Fatalf("parsePeers = %v, want %v", got, want)
	}
}

func TestConfiguredNetworkMagic(t *testing.T) {
	for name, want := range map[string]wire.BitcoinNet{
		"mainnet": wire.MainNet, "testnet": wire.TestNet3,
		"testnet3": wire.TestNet3, "testnet4": wire.TestNet4,
		"signet": wire.SigNet, "regtest": wire.TestNet,
	} {
		if got := btcNetworkMap[name]; got != want {
			t.Fatalf("btcNetworkMap[%q] = 0x%08x, want 0x%08x", name, uint32(got), uint32(want))
		}
	}
}

func TestReplaceVersionUserAgentPreservesOptionalTail(t *testing.T) {
	original := encodeWirePayload(t, getVersionMsg())
	original = original[:len(original)-1] // omit the optional relay flag
	wantUserAgent := "/replacement:1.0/"

	modified, err := replaceVersionUserAgent(original, wantUserAgent)
	if err != nil {
		t.Fatalf("replaceVersionUserAgent err: %s", err)
	}
	message, err := bip324_transport.DecodeWireMessageFromBuf(wire.CmdVersion, modified)
	if err != nil {
		t.Fatalf("decode modified version: %s", err)
	}
	version := message.(*wire.MsgVersion)
	if version.UserAgent != wantUserAgent {
		t.Fatalf("modified user agent = %q, want %q", version.UserAgent, wantUserAgent)
	}
	if !bytes.Equal(modified[len(modified)-4:], original[len(original)-4:]) {
		t.Fatalf("last-block tail changed from %x to %x", original[len(original)-4:], modified[len(modified)-4:])
	}
	if len(modified) != len(original)-len(getVersionMsg().UserAgent)+len(wantUserAgent) {
		t.Fatalf("modified payload length = %d", len(modified))
	}

	withoutUserAgent, err := replaceVersionUserAgent(original[:80], wantUserAgent)
	if err != nil {
		t.Fatalf("replaceVersionUserAgent without existing field: %s", err)
	}
	message, err = bip324_transport.DecodeWireMessageFromBuf(wire.CmdVersion, withoutUserAgent)
	if err != nil {
		t.Fatalf("decode version with added field: %s", err)
	}
	if got := message.(*wire.MsgVersion).UserAgent; got != wantUserAgent {
		t.Fatalf("added user agent = %q, want %q", got, wantUserAgent)
	}

	if _, err := replaceVersionUserAgent(original[:79], wantUserAgent); err == nil {
		t.Fatalf("replaceVersionUserAgent accepted a payload without a user-agent field")
	}
}

func makeV1Header(command string, length uint32) []byte {
	header := make([]byte, v1HeaderLength)
	copy(header[:4], mainnetMagic())
	copy(header[4:16], command)
	binary.LittleEndian.PutUint32(header[16:20], length)
	return header
}

func makeMalformedCommandHeader() []byte {
	header := makeV1Header(wire.CmdPing, 0)
	header[4] = 'p'
	header[5] = 'i'
	header[6] = 0
	header[7] = 'g'
	return header
}

func makeWrongNetworkHeader() []byte {
	header := makeV1Header(wire.CmdPing, 0)
	binary.LittleEndian.PutUint32(header[:4], uint32(wire.TestNet3))
	return header
}

func mainnetMagic() []byte {
	var magic [4]byte
	binary.LittleEndian.PutUint32(magic[:], uint32(wire.MainNet))
	return magic[:]
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func encodeWirePayload(t *testing.T, message wire.Message) []byte {
	t.Helper()
	var payload bytes.Buffer
	if err := message.BtcEncode(&payload, wire.ProtocolVersion, wire.LatestEncoding); err != nil {
		t.Fatalf("encode %s payload: %s", message.Command(), err)
	}
	return payload.Bytes()
}

type readSpyConn struct {
	readCalled      bool
	readDeadlineErr error
}

func (c *readSpyConn) Read([]byte) (int, error) {
	c.readCalled = true
	return 0, io.ErrUnexpectedEOF
}

func (*readSpyConn) Write(b []byte) (int, error)       { return len(b), nil }
func (*readSpyConn) Close() error                      { return nil }
func (*readSpyConn) LocalAddr() net.Addr               { return testAddr("local") }
func (*readSpyConn) RemoteAddr() net.Addr              { return testAddr("remote") }
func (*readSpyConn) SetDeadline(time.Time) error       { return nil }
func (c *readSpyConn) SetReadDeadline(time.Time) error { return c.readDeadlineErr }
func (*readSpyConn) SetWriteDeadline(time.Time) error  { return nil }

type testAddr string

func (a testAddr) Network() string { return string(a) }
func (a testAddr) String() string  { return string(a) }
