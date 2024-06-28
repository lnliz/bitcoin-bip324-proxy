package main

import (
	"net"
	"testing"
	"time"

	bip324_transport "github.com/lnliz/bitcoin-bip324-proxy/transport"
)

var (
	v1VersionMsgPayload = []byte{0x80, 0x11, 0x1, 0x0, 0x4d, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa7, 0xfb, 0x60, 0x66, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xc0, 0xa8, 0x0, 0x1, 0x20, 0x8d, 0x4d, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xb0, 0x38, 0x9f, 0x26, 0x2d, 0xea, 0xf3, 0xd, 0x1b, 0x2f, 0x62, 0x74, 0x63, 0x77, 0x69, 0x72, 0x65, 0x3a, 0x30, 0x2e, 0x35, 0x2e, 0x30, 0x2f, 0x62, 0x74, 0x63, 0x64, 0x3a, 0x30, 0x2e, 0x32, 0x34, 0x2e, 0x32, 0x2f, 0x11, 0x32, 0x2, 0x0, 0x0}
)

type MockV2Peer struct {
	t    *testing.T
	addr string
	ln   net.Listener

	receivedMessages []*bip324_transport.P2pMessage
}

func (s *MockV2Peer) Start() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.ln = ln
	go s.acceptLoop()
	return nil
}

func (s *MockV2Peer) Stop() error {
	return s.ln.Close()
}

func (s *MockV2Peer) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.v2ConnectionHandler(conn)
	}
}

func NewMockV2Peer(addr string, t *testing.T) *MockV2Peer {
	return &MockV2Peer{
		t:                t,
		addr:             addr,
		receivedMessages: []*bip324_transport.P2pMessage{},
	}
}

func (s *MockV2Peer) v2ConnectionHandler(conn net.Conn) {
	s.t.Helper()

	s.t.Logf("v2ConnectionHandler")
	defer conn.Close()

	transport, err := bip324_transport.NewTransport(conn, NetMagicMainnet)
	if err != nil {
		s.t.Fatalf("NewTransport err: %s", err)
		return
	}

	if err := transport.V2Handshake(false); err != nil {
		s.t.Fatalf("V2Handshake: %s", err)
		return
	}

	ourVersionMsg := &bip324_transport.P2pMessage{
		Type:    "version",
		Payload: v1VersionMsgPayload,
	}

	if err := transport.SendV2Message(ourVersionMsg); err != nil {
		s.t.Fatalf("SendV2Message: %s", err)
		return
	}

	msg, err := transport.RecvV2Message()
	if err != nil {
		s.t.Fatalf("v2ConnectionHandler: RecvV2Message err: %s", err)
		return
	}

	/*
		save received messages to inspect later
	*/
	s.receivedMessages = append(s.receivedMessages, msg)

	if msg.Type == "version" {
		s.t.Logf("v2ConnectionHandler: received version")

		verAck := &bip324_transport.P2pMessage{
			Type:    "verack",
			Payload: []byte{},
		}

		if err := transport.SendV2Message(verAck); err != nil {
			s.t.Fatalf("v2ConnectionHandler: SendV2Message err: %s", err)
			return
		}
	}

	s.t.Logf("v2ConnectionHandler - Done")
}

func TestProyWithMockV2Peer(t *testing.T) {
	t.Helper()

	initMetrics(true)

	server := NewMockV2Peer(":7865", t)
	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start mock server: %v", err)
	}
	defer server.Stop()

	remoteAddr := "localhost:7865"

	go startProxyListener("tst", "localhost:7856", remoteAddr, NetMagicMainnet, false, true, true)

	// give listener time to start up
	time.Sleep(500 * time.Millisecond)

	nc, err := net.Dial("tcp", "localhost:7856")
	if err != nil {
		t.Fatalf("Failed to connect to mock v2 peer: %v", err)
	}
	defer nc.Close()

	v1VersionMsg := &bip324_transport.P2pMessage{
		Type:    "version",
		Payload: v1VersionMsgPayload,
	}

	/*
		only to use the convenient SendV1Message() / RecvV1Message() functions
	*/
	c := NewConnectionHandler(NetMagicMainnet, "", nil, false, false, false)

	if err := c.SendV1Message(nc, v1VersionMsg); err != nil {
		t.Fatalf("Failed to send message to mock server: %v", err)
	}

	resp, err := c.RecvV1Message(nc)
	if err != nil {
		t.Fatalf("Failed to RecvV1Message: %v", err)
	}

	if resp.Type != "version" {
		t.Fatalf("Wrong response type: %v", resp.Type)
	}

	resp, err = c.RecvV1Message(nc)
	if err != nil {
		t.Fatalf("Failed to RecvV1Message: %v", err)
	}

	if resp.Type != "verack" {
		t.Fatalf("Wrong response type: %v", resp.Type)
	}

	// give time to digest message
	time.Sleep(500 * time.Millisecond)

	/*
		we expect the one version message we sent above
	*/
	if len(server.receivedMessages) != 1 {
		t.Fatalf("server.receivedMessages: %#v", server.receivedMessages)
	}

	t.Logf("server.receivedMessages comtains %d message(s) - as expected", len(server.receivedMessages))
}
