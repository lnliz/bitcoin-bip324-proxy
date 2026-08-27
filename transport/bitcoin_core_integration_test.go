package transport

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire"
)

func TestInteropWithBitcoinCore(t *testing.T) {
	bitcoind := os.Getenv("BIP324_BITCOIND")
	if bitcoind == "" {
		t.Skip("set BIP324_BITCOIND to run the Bitcoin Core integration test")
	}
	bitcoind, err := exec.LookPath(bitcoind)
	if err != nil {
		t.Fatalf("find bitcoind: %v", err)
	}

	portListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve Bitcoin Core port: %v", err)
	}
	port := portListener.Addr().(*net.TCPAddr).Port
	if err := portListener.Close(); err != nil {
		t.Fatalf("release Bitcoin Core port: %v", err)
	}

	dataDir := t.TempDir()
	logPath := filepath.Join(dataDir, "integration-bitcoind.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create Bitcoin Core log: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	cmd := exec.CommandContext(ctx, bitcoind,
		"-regtest",
		"-datadir="+dataDir,
		"-bind="+address,
		"-port="+strconv.Itoa(port),
		"-listen=1",
		"-discover=0",
		"-dnsseed=0",
		"-fixedseeds=0",
		"-listenonion=0",
		"-server=0",
		"-v2transport=1",
		"-printtoconsole=1",
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		cancel()
		_ = logFile.Close()
		t.Fatalf("start Bitcoin Core: %v", err)
	}

	processDone := make(chan struct{})
	var processErr error
	go func() {
		processErr = cmd.Wait()
		close(processDone)
	}()

	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			cancel()
			select {
			case <-processDone:
			case <-time.After(5 * time.Second):
				_ = cmd.Process.Kill()
				<-processDone
			}
			_ = logFile.Close()
		})
	}
	t.Cleanup(func() {
		stop()
		if t.Failed() {
			if output, err := os.ReadFile(logPath); err == nil {
				t.Logf("Bitcoin Core output:\n%s", output)
			}
		}
	})

	var conn net.Conn
	startupDeadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(startupDeadline) {
		select {
		case <-processDone:
			t.Fatalf("Bitcoin Core exited during startup: %v", processErr)
		default:
		}

		conn, err = net.DialTimeout("tcp4", address, 200*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if conn == nil {
		t.Fatalf("Bitcoin Core did not listen on %s: %v", address, err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("set Bitcoin Core test deadline: %v", err)
	}

	local, err := NewTransport(conn, uint32(wire.TestNet), true)
	if err != nil {
		t.Fatalf("create local v2 transport: %v", err)
	}
	defer local.Destroy()
	if err := local.V2Handshake(); err != nil {
		t.Fatalf("handshake with Bitcoin Core: %v", err)
	}
	if len(local.SessionID()) != 32 {
		t.Fatalf("Bitcoin Core handshake produced invalid session ID length")
	}

	coreAddress := wire.NewNetAddressIPPort(net.ParseIP("127.0.0.1"), uint16(port), 0)
	localAddress := wire.NewNetAddressIPPort(net.ParseIP("127.0.0.1"), 0, 0)
	version := wire.NewMsgVersion(localAddress, coreAddress, uint64(time.Now().UnixNano()), 0)
	if err := version.AddUserAgent("bip324-integration", "1.0"); err != nil {
		t.Fatalf("construct local version: %v", err)
	}
	if err := local.SendV2Message(version); err != nil {
		t.Fatalf("send version to Bitcoin Core: %v", err)
	}

	gotVersion := false
	gotVerAck := false
	for messages := 0; messages < 20 && !gotVerAck; messages++ {
		message, err := local.RecvV2P2pMessage()
		if err != nil {
			t.Fatalf("receive Bitcoin Core application message: %v", err)
		}

		switch message.Type {
		case wire.CmdVersion:
			if gotVersion {
				t.Fatalf("Bitcoin Core sent version more than once")
			}
			decoded, err := DecodeWireMessageFromBuf(message.Type, message.Payload)
			if err != nil {
				t.Fatalf("decode Bitcoin Core version: %v", err)
			}
			if _, ok := decoded.(*wire.MsgVersion); !ok {
				t.Fatalf("decoded Bitcoin Core version as %T", decoded)
			}
			gotVersion = true
			if err := local.SendV2Message(&wire.MsgVerAck{}); err != nil {
				t.Fatalf("send verack to Bitcoin Core: %v", err)
			}

		case wire.CmdVerAck:
			if !gotVersion {
				t.Fatalf("Bitcoin Core sent verack before version")
			}
			gotVerAck = true
		}
	}
	if !gotVersion || !gotVerAck {
		t.Fatalf("incomplete Bitcoin application handshake: version=%v verack=%v", gotVersion, gotVerAck)
	}

	t.Logf("completed BIP324 and application handshake with %s on %s", bitcoind, address)
}
