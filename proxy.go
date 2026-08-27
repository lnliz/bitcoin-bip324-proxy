package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	bip324_transport "github.com/lnliz/bitcoin-bip324-proxy/transport"

	"github.com/btcsuite/btcd/wire"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type ConnectionHandler struct {
	log zerolog.Logger

	btcNet      wire.BitcoinNet
	btcNetBytes []byte

	transport *bip324_transport.V2Transport

	useRemoteAddr  string
	peerRemoteAddr string

	v1ProtocolOnly  bool
	v2ProtocolOnly  bool
	metricsInclPeer bool

	appendUserAgentString bool

	connLocal  net.Conn
	dialRemote func(string) (net.Conn, error)
}

const (
	proxyUserAgentName    = "bip324-proxy"
	proxyUserAgentVersion = "0.1"
	remoteDialTimeout     = 10 * time.Second
	v2HandshakeTimeout    = 30 * time.Second
	localVersionTimeout   = 30 * time.Second
)

var (
	conId atomic.Uint64
)

func NewConnectionHandler(btcNet wire.BitcoinNet, useRemoteAddr string, nc net.Conn, v1ProtoOnly bool, v2ProtoOnly bool, metricsInclPeerInfo bool, appendUserAgentString bool) *ConnectionHandler {
	initMetrics(metricsInclPeerInfo)
	nm := make([]byte, 4)
	binary.LittleEndian.PutUint32(nm, uint32(btcNet))
	return &ConnectionHandler{
		log:                   log.With().Int("conId", int(conId.Add(1))).Logger(),
		useRemoteAddr:         useRemoteAddr,
		connLocal:             nc,
		v1ProtocolOnly:        v1ProtoOnly,
		v2ProtocolOnly:        v2ProtoOnly,
		metricsInclPeer:       metricsIncludePeerLabel,
		appendUserAgentString: appendUserAgentString,
		btcNet:                btcNet,
		btcNetBytes:           nm,
		dialRemote: func(address string) (net.Conn, error) {
			return net.DialTimeout("tcp", address, remoteDialTimeout)
		},
	}
}

const (
	v1HeaderLength = 24
)

func (c *ConnectionHandler) Infof(msg string, args ...interface{}) {
	c.log.Info().Msgf(msg, args...)
}

func (c *ConnectionHandler) Debugf(msg string, args ...interface{}) {
	c.log.Debug().Msgf(msg, args...)
}

func (c *ConnectionHandler) Tracef(msg string, args ...interface{}) {
	c.log.Trace().Msgf(msg, args...)
}

func (c *ConnectionHandler) InitTransport(peerConn net.Conn) error {
	var err error
	c.transport, err = bip324_transport.NewTransport(peerConn, uint32(c.btcNet), true)
	return err
}

func (c *ConnectionHandler) dial(address string) (net.Conn, error) {
	if c.dialRemote != nil {
		return c.dialRemote(address)
	}
	return net.DialTimeout("tcp", address, remoteDialTimeout)
}

func (c *ConnectionHandler) handleLocalConnection() {
	if c.connLocal == nil {
		c.Infof("local connection is nil")
		return
	}
	if c.v1ProtocolOnly && c.v2ProtocolOnly {
		c.Infof("v1-only and v2-only cannot both be enabled")
		_ = c.connLocal.Close()
		return
	}

	defer func() {
		c.Infof("closing %s", c.connLocal.RemoteAddr())
		_ = c.connLocal.Close()
	}()
	defer func() {
		if c.transport != nil {
			c.transport.Destroy()
			c.transport = nil
		}
	}()

	c.Infof("handleLocalConnection, local: %s", c.connLocal.RemoteAddr())
	c.Infof("handleLocalConnection, remote upstream: %s", c.useRemoteAddr)

	if err := c.connLocal.SetReadDeadline(time.Now().Add(localVersionTimeout)); err != nil {
		c.Infof("failed to set local version deadline: %s", err)
		return
	}

	header, err := bip324_transport.ReadData(c.connLocal, v1HeaderLength)
	if err != nil {
		c.Infof("read initial v1 header: %s", err)
		return
	}

	v1WireMsg, firstCommand, firstPayload, err := c.RecvV1MessageWithHeader(header, c.connLocal)
	if err != nil {
		c.Infof("c.RecvV1MessageWithHeader() err: %s", err)
		return
	}
	if err := c.connLocal.SetReadDeadline(time.Time{}); err != nil {
		c.Infof("failed to clear local version deadline: %s", err)
		return
	}

	v1DecodedVersionMsg, ok := v1WireMsg.(*wire.MsgVersion)
	if !ok {
		c.Infof("first message needs to be VERSION, found: %s", v1WireMsg.Command())
		return
	}
	firstMessage := &bip324_transport.P2pMessage{
		Type:    firstCommand,
		Payload: firstPayload,
	}

	remoteAddr := net.JoinHostPort(v1DecodedVersionMsg.AddrYou.IP.String(), fmt.Sprintf("%d", v1DecodedVersionMsg.AddrYou.Port))
	if c.useRemoteAddr != "" {
		c.Infof("using upstream: %s", c.useRemoteAddr)
		remoteAddr = c.useRemoteAddr
	}

	c.Infof("Local client connected")
	c.Infof("peerRemoteAddr: %s ", remoteAddr)
	c.Infof("localUserAgent: %s ", v1DecodedVersionMsg.UserAgent)

	if c.appendUserAgentString {
		if err := v1DecodedVersionMsg.AddUserAgent(proxyUserAgentName, proxyUserAgentVersion); err != nil {
			c.Infof("failed to append proxy user agent: %s", err)
			return
		}
		c.Debugf("Using user agent %s", v1DecodedVersionMsg.UserAgent)

		modifiedPayload, err := replaceVersionUserAgent(firstMessage.Payload, v1DecodedVersionMsg.UserAgent)
		if err != nil {
			c.Infof("failed to modify version user agent: %s", err)
			return
		}
		firstMessage.Payload = modifiedPayload
	}

	peerConn, err := c.dial(remoteAddr)
	if err != nil {
		protocol := "v2"
		if c.v1ProtocolOnly {
			protocol = "v1"
		}
		metricProxyConnectionsOutErrors.WithLabelValues(protocol).Inc()
		c.Infof("Error connecting to destination: %s", err)
		return
	}
	defer func() {
		if peerConn != nil {
			_ = peerConn.Close()
		}
	}()
	c.Infof("Remote client connected")
	c.log = c.log.With().Str("peer", remoteAddr).Logger()

	c.peerRemoteAddr = remoteAddr

	gotV2Connection := false
	if c.v1ProtocolOnly {
		c.Infof("forcing v1-only connection")
	} else {
		if err := c.InitTransport(peerConn); err != nil {
			c.Infof("c.InitTransport err: %s", err)
			return
		}
		gotV2Connection = true
		c.Infof("try V2Handshake")

		handshakeErr := peerConn.SetDeadline(time.Now().Add(v2HandshakeTimeout))
		if handshakeErr != nil {
			handshakeErr = fmt.Errorf("set v2 handshake deadline: %w", handshakeErr)
		} else {
			handshakeErr = c.transport.V2Handshake()
			if err := peerConn.SetDeadline(time.Time{}); err != nil && handshakeErr == nil {
				handshakeErr = fmt.Errorf("clear v2 handshake deadline: %w", err)
			}
		}

		if handshakeErr != nil {
			gotV2Connection = false
			c.Infof("transport.V2Handshake() err: %s", handshakeErr)
			c.transport.Destroy()
			c.transport = nil

			_ = peerConn.Close()
			if c.v2ProtocolOnly {
				c.Infof("v2-only connection - disconnecting")
				return
			}

			// reconnect for a v1<->v1 only connection
			peerConn, err = c.dial(remoteAddr)
			if err != nil {
				metricProxyConnectionsOutErrors.WithLabelValues("v1").Inc()
				c.Infof("failed to re-connect")
				return
			}
			c.Infof("reconnected to %s", remoteAddr)

			metricProxyConnectionsV1Fallbacks.WithLabelValues().Inc()
			c.Infof("falling back to v1")
		}
	}

	if gotV2Connection {
		c.Infof("V2Handshake successful - starting v2 connection")
		metricProxyConnectionsOut.WithLabelValues("v2").Inc()

		if err := c.transport.SendV2MessageBuf(firstMessage.Type, firstMessage.Payload); err != nil {
			c.Infof("c.SendV2Message(lastV1Message) err: %s", err)
			return
		}

		c.v2MainLoop(peerConn)
	} else {
		c.Infof("Starting v1 connection")
		metricProxyConnectionsOut.WithLabelValues("v1").Inc()

		if err := c.SendV1MessageBytes(peerConn, firstMessage); err != nil {
			c.Infof("SendV1Message err: %s", err)
			return
		}

		c.v1MainLoop(peerConn)
	}
}

func replaceVersionUserAgent(payload []byte, userAgent string) ([]byte, error) {
	// version, services, timestamp, AddrYou, AddrMe, and nonce occupy 80
	// bytes. A user-agent field can only be present after all of them.
	const userAgentOffset = 80
	if len(payload) < userAgentOffset {
		return nil, fmt.Errorf("version payload has no user-agent field")
	}

	oldUserAgentEnd := userAgentOffset
	oldLength := uint64(0)
	if len(payload) > userAgentOffset {
		remaining := bytes.NewReader(payload[userAgentOffset:])
		var err error
		oldLength, err = wire.ReadVarInt(remaining, wire.ProtocolVersion)
		if err != nil {
			return nil, fmt.Errorf("read user-agent length: %w", err)
		}
		if oldLength > uint64(remaining.Len()) {
			return nil, fmt.Errorf("user-agent length %d exceeds remaining version payload %d", oldLength, remaining.Len())
		}
		lengthFieldSize := len(payload[userAgentOffset:]) - remaining.Len()
		oldUserAgentEnd += lengthFieldSize + int(oldLength)
	}

	var modified bytes.Buffer
	modified.Grow(len(payload) - int(oldLength) + len(userAgent) + wire.MaxVarIntPayload)
	_, _ = modified.Write(payload[:userAgentOffset])
	if err := wire.WriteVarString(&modified, wire.ProtocolVersion, userAgent); err != nil {
		return nil, fmt.Errorf("write user agent: %w", err)
	}
	_, _ = modified.Write(payload[oldUserAgentEnd:])
	return modified.Bytes(), nil
}

func (c *ConnectionHandler) SendV1Message(nc net.Conn, m wire.Message) error {
	pver := wire.ProtocolVersion
	err := wire.WriteMessage(nc, m, pver, c.btcNet)
	return err
}

func (c *ConnectionHandler) RecvV1MessageWithHeader(header []byte, nc net.Conn) (wire.Message, string, []byte, error) {
	if len(header) != v1HeaderLength {
		return nil, "", nil, fmt.Errorf("invalid v1 header length: got %d, want %d", len(header), v1HeaderLength)
	}
	if !bytes.Equal(header[0:4], c.btcNetBytes) {
		return nil, "", nil, fmt.Errorf("invalid net magic bytes")
	}
	command, err := bip324_transport.DecodeCommand(header[4:16])
	if err != nil {
		return nil, "", nil, fmt.Errorf("invalid v1 command: %w", err)
	}
	if command != wire.CmdVersion {
		return nil, "", nil, fmt.Errorf("first message needs to be VERSION, found: %s", command)
	}
	length := binary.LittleEndian.Uint32(header[16:20])
	maxVersionPayload := (&wire.MsgVersion{}).MaxPayloadLength(wire.ProtocolVersion)
	if length > maxVersionPayload {
		return nil, "", nil, fmt.Errorf("version payload is too large: %d > %d", length, maxVersionPayload)
	}

	p2pMessage, err := c.recvV1P2pMessageWithHeader(header, nc)
	if err != nil {
		return nil, "", nil, err
	}

	c.Tracef("RecvV1MessageWithHeader() cmd: %s", p2pMessage.Type)
	version := &wire.MsgVersion{}
	payloadReader := bytes.NewBuffer(p2pMessage.Payload)
	err = version.BtcDecode(payloadReader, wire.ProtocolVersion, wire.LatestEncoding)
	if err != nil {
		c.Tracef("decode initial version err: %s", err)
		return nil, p2pMessage.Type, p2pMessage.Payload, err
	}
	// Unknown trailing version fields are preserved in p2pMessage.Payload. The
	// current fields are only decoded so the proxy can select its destination.
	return version, p2pMessage.Type, p2pMessage.Payload, nil
}

func (c *ConnectionHandler) recvV1P2pMessageWithHeader(header []byte, nc net.Conn) (*bip324_transport.P2pMessage, error) {
	if len(header) != v1HeaderLength {
		return nil, fmt.Errorf("invalid v1 header length: got %d, want %d", len(header), v1HeaderLength)
	}
	if nc == nil {
		return nil, fmt.Errorf("connection is nil")
	}
	if !bytes.Equal(header[0:4], c.btcNetBytes) {
		return nil, fmt.Errorf("invalid net magic bytes")
	}

	length := binary.LittleEndian.Uint32(header[16:20])
	if length > wire.MaxMessagePayload {
		return nil, fmt.Errorf("v1 payload is too large: %d > %d", length, wire.MaxMessagePayload)
	}

	msgCmd, err := bip324_transport.DecodeCommand(header[4:16])
	if err != nil {
		return nil, fmt.Errorf("invalid v1 command: %w", err)
	}

	payload, err := bip324_transport.ReadData(nc, int(length))
	if err != nil {
		return nil, err
	}

	receivedChecksum := header[20:24]
	calculatedChecksum := bip324_transport.DoubleHashB(payload)[0:4]
	if !bytes.Equal(receivedChecksum, calculatedChecksum) {
		return nil, fmt.Errorf("checksum mismatch")
	}

	return &bip324_transport.P2pMessage{Type: msgCmd, Payload: payload}, nil
}

func (c *ConnectionHandler) RecvV1Message(conn net.Conn) (wire.Message, string, []byte, error) {
	p2pMessage, err := c.recvV1P2pMessage(conn)
	if err != nil {
		return nil, "", nil, err
	}
	v1Msg, err := bip324_transport.DecodeWireMessageFromBuf(p2pMessage.Type, p2pMessage.Payload)
	return v1Msg, p2pMessage.Type, p2pMessage.Payload, err
}

func (c *ConnectionHandler) recvV1P2pMessage(conn net.Conn) (*bip324_transport.P2pMessage, error) {
	header, err := bip324_transport.ReadData(conn, v1HeaderLength)
	if err != nil {
		return nil, fmt.Errorf("error reading header: %w", err)
	}
	c.Tracef("RecvV1Message() header received")
	return c.recvV1P2pMessageWithHeader(header, conn)
}

func (c *ConnectionHandler) v1MainLoop(remoteConn net.Conn) {
	c.Infof("v1MainLoop")
	c.mainLoop(false, remoteConn)
}

func (c *ConnectionHandler) v2MainLoop(remoteConn net.Conn) {
	c.Infof("v2MainLoop")
	c.mainLoop(true, remoteConn)
}

func (c *ConnectionHandler) SendV1MessageBytes(nc net.Conn, m *bip324_transport.P2pMessage) error {
	encoded, err := m.EncodeAsV1()
	if err != nil {
		return err
	}
	buf := make([]byte, 0, len(c.btcNetBytes)+len(encoded))
	buf = append(buf, c.btcNetBytes...)
	buf = append(buf, encoded...)
	c.Tracef("SendV1MessageBytes sending len(buf) bytes: %d", len(buf))
	return bip324_transport.WriteData(nc, buf)
}

func (c *ConnectionHandler) mainLoop(remoteIsV2 bool, remotePeerConn net.Conn) {
	remoteProtoVersion := "v1"
	if remoteIsV2 {
		remoteProtoVersion = "v2"
	}

	type relayEvent struct {
		msg       *bip324_transport.P2pMessage
		fromLocal bool
		err       error
	}

	events := make(chan relayEvent, 2)
	done := make(chan struct{})
	var readers sync.WaitGroup
	readers.Add(2)
	defer func() {
		close(done)
		_ = c.connLocal.Close()
		if remotePeerConn != nil {
			_ = remotePeerConn.Close()
		}
		readers.Wait()
	}()

	forwardEvent := func(event relayEvent) bool {
		select {
		case events <- event:
			return true
		case <-done:
			return false
		}
	}

	go func() {
		defer readers.Done()
		for {
			var m *bip324_transport.P2pMessage
			var err error

			if remoteIsV2 {
				m, err = c.transport.RecvV2P2pMessage()
			} else {
				m, err = c.recvV1P2pMessage(remotePeerConn)
			}

			if err != nil {
				forwardEvent(relayEvent{err: err})
				return
			}
			c.metricMsgReceived(remoteProtoVersion, m.Type, "remote", len(m.Payload))

			if !forwardEvent(relayEvent{msg: m}) {
				return
			}
		}
	}()

	go func() {
		defer readers.Done()
		for {
			m, err := c.recvV1P2pMessage(c.connLocal)
			if err != nil {
				forwardEvent(relayEvent{fromLocal: true, err: err})
				return
			}
			c.metricMsgReceived("v1", m.Type, "local", len(m.Payload))
			if !forwardEvent(relayEvent{msg: m, fromLocal: true}) {
				return
			}
		}
	}()

	for {
		event := <-events
		if event.err != nil {
			c.Infof("main loop receive error: %s", event.err)
			return
		}

		msg := event.msg
		if event.fromLocal {
			if remoteIsV2 {
				if err := c.transport.SendV2MessageBuf(msg.Type, msg.Payload); err != nil {
					c.Infof("send v2 message to remote: %s", err)
					return
				}
			} else {
				if err := c.SendV1MessageBytes(remotePeerConn, msg); err != nil {
					c.Infof("send v1 message to remote: %s", err)
					return
				}
			}
			c.metricMsgSent(remoteProtoVersion, msg.Type, "remote", len(msg.Payload))
			continue
		}

		if err := c.SendV1MessageBytes(c.connLocal, msg); err != nil {
			c.Infof("send v1 message to local: %s", err)
			return
		}
		c.metricMsgSent("v1", msg.Type, "local", len(msg.Payload))
	}
}
