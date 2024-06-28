package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"

	bip324_transport "github.com/lnliz/bitcoin-bip324-proxy/transport"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type ConnectionHandler struct {
	netMagic []byte

	log zerolog.Logger

	transport *bip324_transport.V2Transport

	useRemoteAddr  string
	peerRemoteAddr string

	v1ProtocolOnly  bool
	v2ProtocolOnly  bool
	metricsInclPeer bool

	connLocal net.Conn
}

func NewConnectionHandler(netMagic []byte, useRemoteAddr string, nc net.Conn, v1ProtoOnly bool, v2ProtoOnly bool, metricsInclPeerInfo bool) *ConnectionHandler {
	return &ConnectionHandler{
		log: log.With().Int("conId", int(conId.Add(1))).Logger(),

		useRemoteAddr:   useRemoteAddr,
		connLocal:       nc,
		v1ProtocolOnly:  v1ProtoOnly,
		v2ProtocolOnly:  v2ProtoOnly,
		metricsInclPeer: metricsInclPeerInfo,
		netMagic:        netMagic,
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

func (c *ConnectionHandler) InitTransport(peerConn net.Conn) error {
	var err error
	c.transport, err = bip324_transport.NewTransport(peerConn, c.netMagic)
	return err
}

var (
	conId atomic.Uint64
)

func (c *ConnectionHandler) handleLocalConnection() {
	defer func() {
		c.Infof("closing %s", c.connLocal.RemoteAddr())
		c.connLocal.Close()
	}()

	c.Infof("handleLocalConnection, local: %s", c.connLocal.RemoteAddr())
	c.Infof("handleLocalConnection, remote upstream: %s", c.useRemoteAddr)

	v1VersionSuffix := []byte("version\x00\x00\x00\x00\x00")
	v1Prefix := append(c.netMagic, v1VersionSuffix...)

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

	remainingBytesLen := v1HeaderLength - len(header)
	remainingBytes, err := bip324_transport.ReadData(c.connLocal, remainingBytesLen)
	if err != nil {
		c.Infof("read remainingBytesLen err: %s", err)
		return
	}

	header = append(header, remainingBytes...)

	v1Msg, err := c.RecvV1MessageWithHeader(header, c.connLocal)
	if err != nil {
		c.Infof("c.RecvV1Message(brClient) - got an err: %s", err)
		return
	}

	addrBytes := v1Msg.Payload[20:46]
	remoteAddrIpv6 := addrBytes[8:24]

	remoteIpBytes := remoteAddrIpv6[len(remoteAddrIpv6)-4:]
	remoteIPStr := net.IP(remoteIpBytes).String()
	remotePort := binary.BigEndian.Uint16(addrBytes[24:26])
	remoteAddr := fmt.Sprintf("%s:%d", remoteIPStr, remotePort)

	localUserAgent := string(v1Msg.Payload[81 : 81+int(v1Msg.Payload[80])])

	if c.useRemoteAddr != "" {
		c.Infof("using upstream: %s", c.useRemoteAddr)
		remoteAddr = c.useRemoteAddr
	}

	c.Infof("Local client connected")
	c.Infof("peerRemoteAddr: %s ", remoteAddr)
	c.Infof("localUserAgent: %s ", localUserAgent)

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
		gotV2Connection = false
	} else {
		c.Infof("try V2Handshake")

		if err := c.transport.V2Handshake(true); err != nil {
			gotV2Connection = false
			c.Infof("transport.V2Handshake() err: %s", err)

			peerConn.Close()
			if c.v2ProtocolOnly {
				c.Infof("no fallback to v1, disconnecting")
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

			if err := c.SendV1Message(peerConn, v1Msg); err != nil {
				c.Infof("Send v1 message err: %s", err)
				return
			}
		}
	}

	if gotV2Connection {
		c.Infof("Starting v2 connection")
		metricProxyConnectionsOut.WithLabelValues("v2").Inc()

		if err := c.transport.SendV2Message(v1Msg); err != nil {
			c.Infof("c.SendV2Message(lastV1Message) err: %s", err)
			return
		}

		c.v2MainLoop()
	} else {
		c.Infof("Starting v1 connection")
		metricProxyConnectionsOut.WithLabelValues("v1").Inc()

		if err := c.SendV1Message(peerConn, v1Msg); err != nil {
			c.Infof("SendV1Message err: %s", err)
			return
		}

		c.v1MainLoop(peerConn)
	}
}

func (c *ConnectionHandler) SendV1Message(nc net.Conn, m *bip324_transport.P2pMessage) error {
	buf := append(c.netMagic[:], m.EncodeAsV1()...)
	return bip324_transport.SendData(nc, buf)
}

func (c *ConnectionHandler) RecvV1MessageWithHeader(header []byte, nc net.Conn) (*bip324_transport.P2pMessage, error) {
	if !bytes.Equal(header[0:4], c.netMagic) {
		return nil, fmt.Errorf("invalid net magic bytes")
	}

	length := int(binary.LittleEndian.Uint32(header[16:20]))
	payload, err := bip324_transport.ReadData(nc, length)
	if err != nil {
		return nil, err
	}

	// Checksum
	receivedChecksum := header[20:24]
	calculatedChecksum := bip324_transport.DoubleHashB(payload)[0:4]
	if !bytes.Equal(receivedChecksum, calculatedChecksum) {
		return nil, fmt.Errorf("checksum mismatch")
	}

	msgtype := string(bytes.TrimRight(header[4:16], "\x00"))
	return &bip324_transport.P2pMessage{
		Type:    msgtype,
		Payload: payload,
	}, nil
}

func (c *ConnectionHandler) RecvV1Message(conn net.Conn) (*bip324_transport.P2pMessage, error) {
	header, err := bip324_transport.ReadData(conn, v1HeaderLength)
	if err != nil {
		return nil, fmt.Errorf("Error reading header: %w", err)
	}

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

func (c *ConnectionHandler) mainLoop(remoteIsV2 bool, v1RemotePeerCon net.Conn) {
	chanSendToLocal := make(chan *bip324_transport.P2pMessage)
	chanSendToRemote := make(chan *bip324_transport.P2pMessage)
	errChan := make(chan error)

	remoteProtoVersion := "v1"
	if remoteIsV2 {
		remoteProtoVersion = "v2"
	}

	go func() {
		for {
			var msg *bip324_transport.P2pMessage
			var err error

			if remoteIsV2 {
				msg, err = c.transport.RecvV2Message()
			} else {
				msg, err = c.RecvV1Message(v1RemotePeerCon)
			}
			if err != nil {
				c.Infof("c.RecvV2Message() err: %s", err)
				errChan <- err
				close(chanSendToLocal)
				return
			}
			c.metricMsgReceived(remoteProtoVersion, msg.Type, "remote")
			chanSendToLocal <- msg
		}
	}()

	go func() {
		for {
			msg, err := c.RecvV1Message(c.connLocal)
			if err != nil {
				c.Infof("c.RecvV1Message(c.connLocal) err: %s", err)
				errChan <- err
				close(chanSendToRemote)
				return
			}
			c.metricMsgReceived("v1", msg.Type, "local")

			chanSendToRemote <- msg
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
			if err := c.SendV1Message(c.connLocal, msg); err != nil {
				c.Infof("SendV1Message() err: %s", err)
				errChan <- err
				break
			}
			c.metricMsgSent("v1", msg.Type, "local")

		case msg, ok := <-chanSendToRemote:
			if !ok {
				c.Infof("chanSendToRemote closed")
				errChan <- fmt.Errorf("chanSendToRemote closed")
				break
			}
			if remoteIsV2 {
				if err := c.transport.SendV2Message(msg); err != nil {
					c.Infof("SendV2Message(connRemote) err: %s", err)
					errChan <- err
					break
				}
			} else {
				if err := c.SendV1Message(v1RemotePeerCon, msg); err != nil {
					c.Infof("SendV1Message(v1RemotePeerCon) err: %s", err)
					errChan <- err
					return
				}
			}
			c.metricMsgSent(remoteProtoVersion, msg.Type, "remote")

		case err := <-errChan:
			if err != nil {
				c.Infof("v2MainLoop err: %s", err)
				shouldExit = true
				break
			}
		}
		if shouldExit {
			break
		}
	}

	c.Infof("v2MainLoop Done")
}
