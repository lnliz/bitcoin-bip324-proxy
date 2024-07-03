package main

import (
	"net"
	"testing"
	"time"

	bip324_transport "github.com/lnliz/bitcoin-bip324-proxy/transport"

	"github.com/btcsuite/btcd/wire"
)

type MockV2Peer struct {
	t    *testing.T
	addr string
	ln   net.Listener

	receivedV2Messages []wire.Message
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
		t:                  t,
		addr:               addr,
		receivedV2Messages: []wire.Message{},
	}
}

func getVersionMsg() wire.Message {
	you := wire.NewNetAddress(&net.TCPAddr{IP: net.ParseIP("192.168.0.1"), Port: 8333}, wire.SFNodeNetwork)
	you.Timestamp = time.Time{}
	me := wire.NewNetAddress(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8333}, wire.SFNodeNetwork)
	me.Timestamp = time.Time{}
	versionMsg := wire.NewMsgVersion(me, you, 876543, 1234)
	return versionMsg
}

func (s *MockV2Peer) v2ConnectionHandler(conn net.Conn) {
	s.t.Helper()

	s.t.Logf("v2ConnectionHandler")
	defer conn.Close()

	transport, err := bip324_transport.NewTransport(conn, uint32(wire.MainNet), false)
	if err != nil {
		s.t.Fatalf("NewTransport err: %s", err)
		return
	}

	if err := transport.V2Handshake(); err != nil {
		s.t.Fatalf("V2Handshake: %s", err)
		return
	}

	versionMsg := getVersionMsg()
	if err := transport.SendV2Message(versionMsg); err != nil {
		s.t.Fatalf("SendV2Message: %s", err)
		return
	}

	msg, _, _, err := transport.RecvV2Message()
	if err != nil {
		s.t.Fatalf("v2ConnectionHandler: RecvV2Message err: %s", err)
		return
	}

	/*
		save received messages to inspect later
	*/
	s.receivedV2Messages = append(s.receivedV2Messages, msg)

	if msg.Command() == "version" {
		s.t.Logf("v2ConnectionHandler: received version, sending VERACK")

		verAck := wire.NewMsgVerAck()
		if err := transport.SendV2Message(verAck); err != nil {
			s.t.Fatalf("v2ConnectionHandler: SendV2Message err: %s", err)
			return
		}
	}

	msg, _, _, err = transport.RecvV2Message()
	if err != nil {
		s.t.Fatalf("v2ConnectionHandler: RecvV2Message err: %s", err)
		return
	}
	s.receivedV2Messages = append(s.receivedV2Messages, msg)

	if msg.Command() == "ping" {
		s.t.Logf("v2ConnectionHandler: received version, sending VERACK")

		msgPong := wire.NewMsgPong(321)
		if err := transport.SendV2Message(msgPong); err != nil {
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

	go startProxyListener("tst", "localhost:7856", remoteAddr, wire.MainNet, false, true, true)

	// give listener time to start up
	time.Sleep(500 * time.Millisecond)

	nc, err := net.Dial("tcp", "localhost:7856")
	if err != nil {
		t.Fatalf("Failed to connect to mock v2 peer: %v", err)
	}
	defer nc.Close()

	/*
		only to use the convenient SendV1Message() / RecvV1Message() functions
	*/
	c := NewConnectionHandler(wire.MainNet, "", nil, false, false, false)

	ourVersionMessage := getVersionMsg()
	if err := c.SendV1Message(nc, ourVersionMessage); err != nil {
		t.Fatalf("Failed to send message to mock server: %v", err)
	}

	msgResp, _, _, err := c.RecvV1Message(nc)
	if err != nil {
		t.Fatalf("Failed to RecvV1Message: %v", err)
	}

	if msgResp.Command() != "version" {
		t.Fatalf("Wrong response command: %v", msgResp.Command())
	}

	msgResp, _, _, err = c.RecvV1Message(nc)
	if err != nil {
		t.Fatalf("Failed to RecvV1Message: %v", err)
	}

	if msgResp.Command() != "verack" {
		t.Fatalf("Wrong response command: %v", msgResp.Command())
	}

	pingMsg := wire.NewMsgPing(123)

	if err := c.SendV1Message(nc, pingMsg); err != nil {
		t.Fatalf("Failed to send message to mock server: %v", err)
	}

	msgResp, _, _, err = c.RecvV1Message(nc)
	if err != nil {
		t.Fatalf("Failed to RecvV1Message: %v", err)
	}

	if msgResp.Command() != "pong" {
		t.Fatalf("Wrong response command: %v", msgResp.Command())
	}
	// give time to digest message
	time.Sleep(500 * time.Millisecond)

	/*
		we expect version and ping message --> 2
	*/
	if len(server.receivedV2Messages) != 2 {
		t.Fatalf("server.receivedV2Messages: %#v", server.receivedV2Messages)
	}

	t.Logf("server.receivedV2Messages contains %d message(s) - as expected", len(server.receivedV2Messages))
}
