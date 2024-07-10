package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"

	bip324_transport "github.com/lnliz/bitcoin-bip324-proxy/transport"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
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

	connLocal net.Conn
}

const (
	proxyUserAgent = "bip324-proxy:0.1"
)

var (
	conId atomic.Uint64
)

func NewConnectionHandler(btcNet wire.BitcoinNet, useRemoteAddr string, nc net.Conn, v1ProtoOnly bool, v2ProtoOnly bool, metricsInclPeerInfo bool, appendUserAgentString bool) *ConnectionHandler {
	nm := make([]byte, 4)
	binary.LittleEndian.PutUint32(nm, uint32(btcNet))
	return &ConnectionHandler{
		log:                   log.With().Int("conId", int(conId.Add(1))).Logger(),
		useRemoteAddr:         useRemoteAddr,
		connLocal:             nc,
		v1ProtocolOnly:        v1ProtoOnly,
		v2ProtocolOnly:        v2ProtoOnly,
		metricsInclPeer:       metricsInclPeerInfo,
		appendUserAgentString: appendUserAgentString,
		btcNet:                btcNet,
		btcNetBytes:           nm,
	}
}

const (
	v1HeaderLength = 24
)

func (c *ConnectionHandler) Infof(msg string, args ...interface{}) {
	c.log.Info().Msgf(msg, args...)
}

func (c *ConnectionHandler) Debugf(msg string, args ...interface{}) {
	log.Debug().Msgf(msg, args...)
}

func (c *ConnectionHandler) Tracef(msg string, args ...interface{}) {
	log.Trace().Msgf(msg, args...)
}

func (c *ConnectionHandler) InitTransport(peerConn net.Conn) error {
	var err error
	c.transport, err = bip324_transport.NewTransport(peerConn, uint32(c.btcNet), true)
	return err
}

func (c *ConnectionHandler) handleLocalConnection() {
	defer func() {
		c.Infof("closing %s", c.connLocal.RemoteAddr())
		c.connLocal.Close()
	}()

	c.Infof("handleLocalConnection, local: %s", c.connLocal.RemoteAddr())
	c.Infof("handleLocalConnection, remote upstream: %s", c.useRemoteAddr)

	v1VersionSuffix := []byte("version\x00\x00\x00\x00\x00")
	v1Prefix := append(c.btcNetBytes, v1VersionSuffix...)

	var header []byte
	for len(header) < len(v1Prefix) {
		oneByte, err := bip324_transport.ReadData(c.connLocal, 1)
		if err != nil {
			c.Infof("read err: %s", err)
			return
		}
		header = append(header, oneByte...)
		if len(header) < len(v1Prefix) {
			continue
		}

		if !bytes.Equal(header, v1Prefix) {
			c.Infof("V1 prefix mismatch after %d bytes (expected %x got %x), close connection.\n", len(header), v1Prefix, header)
			return
		}
	}

	remainingHeaderBytesLen := v1HeaderLength - len(header)
	remainingBytes, err := bip324_transport.ReadData(c.connLocal, remainingHeaderBytesLen)
	if err != nil {
		c.Infof("read remaining header bytes err: %s", err)
		return
	}

	header = append(header, remainingBytes...)

	v1WireMsg, _, _, err := c.RecvV1MessageWithHeader(header, c.connLocal)
	if err != nil {
		c.Infof("c.RecvV1MessageWithHeader() err: %s", err)
		return
	}

	v1DecodedVersionMsg, ok := v1WireMsg.(*wire.MsgVersion)
	if !ok {
		c.Infof("first message needs to be VERSION, found: %s", v1WireMsg.Command())
		return
	}

	remoteAddr := fmt.Sprintf("%s:%d", v1DecodedVersionMsg.AddrYou.IP.String(), v1DecodedVersionMsg.AddrYou.Port)
	if c.useRemoteAddr != "" {
		c.Infof("using upstream: %s", c.useRemoteAddr)
		remoteAddr = c.useRemoteAddr
	}

	c.Infof("Local client connected")
	c.Infof("peerRemoteAddr: %s ", remoteAddr)
	c.Infof("localUserAgent: %s ", v1DecodedVersionMsg.UserAgent)

	if c.appendUserAgentString {
		v1DecodedVersionMsg.UserAgent = fmt.Sprintf("%s%s/", v1DecodedVersionMsg.UserAgent, proxyUserAgent)
		c.Debugf("Using user agent %s", v1DecodedVersionMsg.UserAgent)
		v1WireMsg = v1DecodedVersionMsg
	}

	peerConn, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		metricProxyConnectionsOutErrors.WithLabelValues("v2").Inc()
		c.Infof("Error connecting to destination: %s", err)
		return
	}
	defer peerConn.Close()
	c.Infof("Remote client connected")
	c.log = c.log.With().Str("peer", remoteAddr).Logger()

	if err := c.InitTransport(peerConn); err != nil {
		c.Infof("c.InitTransport err: %s", err)
		return
	}

	c.peerRemoteAddr = remoteAddr

	gotV2Connection := true
	if c.v1ProtocolOnly {
		c.Infof("forcing v1-only connection")
		gotV2Connection = false
	} else {
		c.Infof("try V2Handshake")

		if err := c.transport.V2Handshake(); err != nil {
			gotV2Connection = false
			c.Infof("transport.V2Handshake() err: %s", err)

			peerConn.Close()
			if c.v2ProtocolOnly {
				c.Infof("v2-only connection - disconencting")
				return
			}

			// reconnect for a v1<->v1 only connection
			peerConn, err = net.Dial("tcp", remoteAddr)
			if err != nil {
				metricProxyConnectionsOutErrors.WithLabelValues("v1").Inc()
				c.Infof("failed to re-connect")
				return
			}
			c.Infof("reconnected to %s", remoteAddr)

			metricProxyConnectionsV1Fallbacks.WithLabelValues().Inc()
			c.Infof("falling back to v1")

			if err := c.SendV1Message(peerConn, v1WireMsg); err != nil {
				c.Infof("Send v1 message err: %s", err)
				return
			}
		}
	}

	if gotV2Connection {
		c.Infof("V2Handshake successful - starting v2 connection")
		metricProxyConnectionsOut.WithLabelValues("v2").Inc()

		if err := c.transport.SendV2Message(v1WireMsg); err != nil {
			c.Infof("c.SendV2Message(lastV1Message) err: %s", err)
			return
		}

		c.v2MainLoop()
	} else {
		c.Infof("Starting v1 connection")
		metricProxyConnectionsOut.WithLabelValues("v1").Inc()

		if err := c.SendV1Message(peerConn, v1WireMsg); err != nil {
			c.Infof("SendV1Message err: %s", err)
			return
		}

		c.v1MainLoop(peerConn)
	}
}

func (c *ConnectionHandler) SendV1Message(nc net.Conn, m wire.Message) error {
	pver := wire.ProtocolVersion
	err := wire.WriteMessage(nc, m, pver, c.btcNet)
	return err
}

func (c *ConnectionHandler) RecvV1MessageWithHeader(header []byte, nc net.Conn) (wire.Message, string, []byte, error) {
	if !bytes.Equal(header[0:4], c.btcNetBytes) {
		return nil, "", nil, fmt.Errorf("invalid net magic bytes")
	}

	length := int(binary.LittleEndian.Uint32(header[16:20]))
	payload, err := bip324_transport.ReadData(nc, length)
	if err != nil {
		return nil, "", nil, err
	}

	// Checksum
	receivedChecksum := header[20:24]
	calculatedChecksum := chainhash.DoubleHashB(payload)[0:4]
	if !bytes.Equal(receivedChecksum, calculatedChecksum) {
		return nil, "", nil, fmt.Errorf("checksum mismatch")
	}

	msgCmd := string(bytes.TrimRight(header[4:16], "\x00"))
	c.Tracef("RecvV1MessageWithHeader() cmd: %s", msgCmd)
	v1Msg, err := bip324_transport.DecodeWireMessageFromBuf(msgCmd, payload)
	if err != nil {
		c.Tracef("DecodeWireMessageFromBuf msgCmd: %s   err: %s", msgCmd, err)
		/*
			we failed to decode the buffer into a wire message
			but can still return "payload" to the caller
		*/
		return nil, msgCmd, payload, err
	}

	return v1Msg, msgCmd, payload, nil
}

func (c *ConnectionHandler) RecvV1Message(conn net.Conn) (wire.Message, string, []byte, error) {
	/*
	   not using wire.ReadMessage, it parses and validates the buffer payload and
	   doesn't know about messages like "wtxidrelay"
	*/
	header, err := bip324_transport.ReadData(conn, v1HeaderLength)
	if err != nil {
		return nil, "", nil, fmt.Errorf("Error reading header: %w", err)
	}
	c.Tracef("RecvV1Message() header received")

	return c.RecvV1MessageWithHeader(header, conn)
}

func (c *ConnectionHandler) v1MainLoop(remoteConn net.Conn) {
	c.Infof("v1MainLoop")
	c.mainLoop(false, remoteConn)
}

func (c *ConnectionHandler) v2MainLoop() {
	c.Infof("v2MainLoop")
	c.mainLoop(true, nil)
}

type P2pMessage struct {
	cmd string
	buf []byte
}

func (m *P2pMessage) EncodeAsV1() []byte {
	var res []byte
	res = append(res, []byte(m.cmd)...)
	res = append(res, make([]byte, 12-len(m.cmd))...)

	payloadLen := uint32(len(m.buf))
	lenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBytes, payloadLen)
	res = append(res, lenBytes...)

	payloadHash := chainhash.DoubleHashB(m.buf)
	res = append(res, payloadHash[:4]...)
	res = append(res, m.buf...)

	return res
}

func (c *ConnectionHandler) SendV1MessageBytes(nc net.Conn, m *P2pMessage) error {
	buf := append(c.btcNetBytes, m.EncodeAsV1()...)
	c.Tracef("SendV1MessageBytes sending len(buf) bytes: %d", len(buf))
	return bip324_transport.WriteData(nc, buf)
}

func (c *ConnectionHandler) mainLoop(remoteIsV2 bool, v1RemotePeerCon net.Conn) {
	chanSendToLocal := make(chan P2pMessage)
	chanSendToRemote := make(chan P2pMessage)
	errChan := make(chan error)

	remoteProtoVersion := "v1"
	if remoteIsV2 {
		remoteProtoVersion = "v2"
	}

	go func() {
		for {
			var m P2pMessage
			var err error

			if remoteIsV2 {
				_, m.cmd, m.buf, err = c.transport.RecvV2Message()
			} else {
				_, m.cmd, m.buf, err = c.RecvV1Message(v1RemotePeerCon)
			}

			/*
				err == wire.ErrUnknownMessage can happen when the btcd code
				doesn't know the message like for "wtxidrelay"
				for that case continue anyway as we have the payload buffer
			*/
			if err != nil && err != wire.ErrUnknownMessage {
				c.Infof("receive message err: %s", err)
				errChan <- err
				close(chanSendToLocal)
				return
			}
			c.metricMsgReceived(remoteProtoVersion, m.cmd, "remote")

			chanSendToLocal <- m
		}
	}()

	go func() {
		for {
			var err error
			var m P2pMessage
			if _, m.cmd, m.buf, err = c.RecvV1Message(c.connLocal); err != nil {
				c.Infof("c.RecvV1Message(c.connLocal) err: %s", err)
				errChan <- err
				close(chanSendToRemote)
				return
			}
			c.metricMsgReceived("v1", m.cmd, "local")
			chanSendToRemote <- m
		}
	}()

	for {
		shouldExit := false
		select {
		case msg, ok := <-chanSendToLocal:
			if !ok {
				c.Infof("chanSendToLocal closed")
				errChan <- fmt.Errorf("chanSendToLocal closed")
				break
			}

			if err := c.SendV1MessageBytes(c.connLocal, &msg); err != nil {
				c.Infof("SendV1Message() err: %s", err)
				errChan <- err
				break
			}
			c.metricMsgSent("v1", msg.cmd, "local")

		case msg, ok := <-chanSendToRemote:
			if !ok {
				c.Infof("chanSendToRemote closed")
				errChan <- fmt.Errorf("chanSendToRemote closed")
				break
			}
			if remoteIsV2 {
				if err := c.transport.SendV2MessageBuf(msg.cmd, msg.buf); err != nil {
					c.Infof("SendV2Message(connRemote) err: %s", err)
					errChan <- err
					break
				}
			} else {
				if err := c.SendV1MessageBytes(v1RemotePeerCon, &msg); err != nil {
					c.Infof("SendV1Message() err: %s", err)
					errChan <- err
					break
				}
			}
			c.metricMsgSent(remoteProtoVersion, msg.cmd, "remote")

		case err := <-errChan:
			if err != nil {
				c.Infof("mainloop err: %s", err)
				shouldExit = true
				break
			}
		}
		if shouldExit {
			break
		}
	}

	c.Infof("mainloop Done")
}
