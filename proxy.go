package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync/atomic"

	bip324_transport "github.com/lnliz/bitcoin-bip324-proxy/transport"
)

type ConnectionHandler struct {
	conId    uint64
	netMagic []byte

	transport *bip324_transport.V2Transport

	useRemoteAddr  string
	peerRemoteAddr string

	v1ProtocolOnly  bool
	v2ProtocolOnly  bool
	metricsInclPeer bool

	connLocal net.Conn
}

func (c *ConnectionHandler) Logf(msg string, args ...interface{}) {
	log.Printf(fmt.Sprintf("conId: %d -> ", c.conId)+msg, args...)
}

func (c *ConnectionHandler) InitTransport(peerConn net.Conn) error {
	var err error
	c.transport, err = bip324_transport.NewTransport(peerConn, c.netMagic)
	return err
}

func (c *ConnectionHandler) tryV2Handshake(lastV1Message *bip324_transport.P2pMessage) error {
	c.Logf("tryV2Handshake")

	if err := c.transport.V2Handshake(true); err != nil {
		c.Logf("V2Handshake() err: %s", err)
		return err
	}

	if err := c.transport.SendV2Message(lastV1Message); err != nil {
		c.Logf("c.SendV2Message(lastV1Message) err: %s", err)
		return err
	}

	c.Logf("tryV2Handshake - success")
	return nil
}

var (
	conId atomic.Uint64
)

func (c *ConnectionHandler) handleLocalConnection() {
	/*
		first, get a new connection ID for logging
	*/
	c.conId = conId.Add(1)

	defer func() {
		c.Logf("closing %s", c.connLocal.RemoteAddr())
		c.connLocal.Close()
	}()

	c.Logf("handleLocalConnection, local: %s", c.connLocal.RemoteAddr())
	c.Logf("handleLocalConnection, remote upstream: %s", c.useRemoteAddr)

	v1VersionSuffix := []byte("version\x00\x00\x00\x00\x00")
	v1Prefix := append(c.netMagic, v1VersionSuffix...)

	var header []byte
	for len(header) < len(v1Prefix) {
		oneByte, err := bip324_transport.ReadData(c.connLocal, 1)
		if err != nil {
			c.Logf("read err: %s", err)
			return
		}
		header = append(header, oneByte...)
		if len(header) < len(v1Prefix) {
			continue
		}

		if !bytes.Equal(header, v1Prefix) {
			c.Logf("V1 prefix mismatch after %d bytes (expected %x got %x), close connection.\n", len(header), v1Prefix, header)
			return
		}
	}

	remainingBytesLen := 24 - len(header)
	remainingBytes, err := bip324_transport.ReadData(c.connLocal, remainingBytesLen)
	if err != nil {
		c.Logf("read remainingBytesLen err: %s", err)
		return
	}

	header = append(header, remainingBytes...)

	v1Msg, err := c.RecvV1MessageWithHeader(header, c.connLocal)
	if err != nil {
		c.Logf("c.RecvV1Message(brClient) - got an err: %s", err)
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
		c.Logf("using upstream: %s", c.useRemoteAddr)
		remoteAddr = c.useRemoteAddr
	}

	c.Logf("Local client connected")
	c.Logf("peerRemoteAddr: %s ", remoteAddr)
	c.Logf("localUserAgent: %s ", localUserAgent)

	peerConn, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		metricProxyConnectionsOutErrors.WithLabelValues("v2").Inc()
		log.Println("Error connecting to destination:", err)
		return
	}
	defer peerConn.Close()
	c.Logf("Remote client connected")

	if err := c.InitTransport(peerConn); err != nil {
		c.Logf("c.InitTransport err: %s", err)
		return
	}

	c.peerRemoteAddr = remoteAddr

	gotV2Connection := true
	if c.v1ProtocolOnly {
		gotV2Connection = false
	} else {
		if err := c.tryV2Handshake(v1Msg); err != nil {
			gotV2Connection = false
			c.Logf("tryV2Handshake err: %s", err)

			peerConn.Close()
			if c.v2ProtocolOnly {
				log.Printf("no fallback to v1, disconnecting")
				return
			}

			// reconnect for a v1<->v1 only connection
			peerConn, err = net.Dial("tcp", remoteAddr)
			if err != nil {
				metricProxyConnectionsOutErrors.WithLabelValues("v1").Inc()
				log.Printf("failed to re-connect")
				return
			}
			c.Logf("reconnected to %s", remoteAddr)

			metricProxyConnectionsV1Fallbacks.WithLabelValues().Inc()
			c.Logf("falling back to v1")

			if err := c.SendV1Message(peerConn, v1Msg); err != nil {
				log.Printf("Send v1 message err: %s", err)
				return
			}
		}
	}

	if gotV2Connection {
		metricProxyConnectionsOut.WithLabelValues("v2").Inc()
		c.v2MainLoop()
	} else {
		metricProxyConnectionsOut.WithLabelValues("v1").Inc()
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
	header, err := bip324_transport.ReadData(conn, 24)
	if err != nil {
		return nil, fmt.Errorf("Error reading header: %w", err)
	}

	return c.RecvV1MessageWithHeader(header, conn)
}

func (c *ConnectionHandler) v2MainLoop() {
	c.Logf("v2MainLoop")

	chanSendToLocal := make(chan *bip324_transport.P2pMessage)
	chanSendToRemote := make(chan *bip324_transport.P2pMessage)
	errChan := make(chan error)

	go func() {
		for {
			msg, err := c.transport.RecvV2Message()
			if err != nil {
				c.Logf("c.RecvV2Message() err: %s", err)
				errChan <- err
				close(chanSendToLocal)
				return
			}
			c.metricMsgReceived("v2", msg.Type, "remote")

			chanSendToLocal <- msg

			/*
				if err := c.SendV1Message(c.connLocal, msg); err != nil {
					c.Logf("SendV1Message() err: %s", err)
				}
				c.metricMsgSent("v1", msg.Type, "local")
			*/
		}
	}()

	go func() {
		for {
			msg, err := c.RecvV1Message(c.connLocal)
			if err != nil {
				c.Logf("c.RecvV1Message(c.connLocal) err: %s", err)
				errChan <- err
				close(chanSendToRemote)
				return
			}
			c.metricMsgReceived("v1", msg.Type, "local")

			chanSendToRemote <- msg

			/*
				if err := c.transport.SendV2Message(msg); err != nil {
					c.Logf("SendV2Message(connRemote) err: %s", err)
					errCh <- err
					return
				}
				c.metricMsgSent("v2", msg.Type, "remote")
			*/
		}
	}()

	for {
		shouldExit := false
		select {
		case msg, ok := <-chanSendToLocal:
			if !ok {
				c.Logf("chanSendToLocal closed")
				errChan <- fmt.Errorf("chanSendToLocal closed")
				break
			}
			if err := c.SendV1Message(c.connLocal, msg); err != nil {
				c.Logf("SendV1Message() err: %s", err)
				errChan <- err
				break
			}
			c.metricMsgSent("v1", msg.Type, "local")

		case msg, ok := <-chanSendToRemote:
			if !ok {
				c.Logf("chanSendToRemote closed")
				errChan <- fmt.Errorf("chanSendToRemote closed")
				break
			}
			if err := c.transport.SendV2Message(msg); err != nil {
				c.Logf("SendV2Message(connRemote) err: %s", err)
				errChan <- err
				break
			}
			c.metricMsgSent("v2", msg.Type, "remote")

		case err := <-errChan:
			if err != nil {
				c.Logf("v2MainLoop err: %s", err)
				shouldExit = true
				break
			}
		}
		if shouldExit {
			break
		}
	}

	c.Logf("v2MainLoop Done")
}

func (c *ConnectionHandler) v1MainLoop(remoteConn net.Conn) {
	c.Logf("v1MainLoop")

	errCh := make(chan error, 2)
	go func() {
		for {
			msg, err := c.RecvV1Message(remoteConn)
			if err != nil {
				c.Logf("RecvV1Message(brDest) err: %s", err)
				errCh <- err
				return
			}
			c.metricMsgReceived("v1", msg.Type, "remote")

			if err := c.SendV1Message(c.connLocal, msg); err != nil {
				c.Logf("SendV1Message(clientCon) err: %s", err)
				errCh <- err
				return
			}
			c.metricMsgSent("v1", msg.Type, "local")
		}
	}()

	go func() {
		for {
			msg, err := c.RecvV1Message(c.connLocal)
			if err != nil {
				c.Logf("c.RecvV1Message(c.connLocal) err: %s", err)
				errCh <- err
				return
			}
			c.metricMsgReceived("v1", msg.Type, "local")

			if err := c.SendV1Message(remoteConn, msg); err != nil {
				c.Logf("SendV1Message(connRemote) err: %s", err)
				errCh <- err
				return
			}
			c.metricMsgSent("v1", msg.Type, "remote")
		}
	}()

	err := <-errCh
	c.Logf("Received error: %s", err)
	c.Logf("Done")
}
