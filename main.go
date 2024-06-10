package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	/*
	   Mainnet: 0xD9B4BEF9
	   Testnet: 0x0709110B
	   Signet: 0x40CF030A
	   Regtest: 0xDAB5BFFA
	*/
	NetMagicMainnet, _ = hex.DecodeString("f9beb4d9")
	NetMagicTestnet, _ = hex.DecodeString("0b110907")
	NetMagicSignet, _  = hex.DecodeString("0a03cf40")
	NetMagicRegtest, _ = hex.DecodeString("fabfb5da")

	NetMagics = map[string][]byte{
		"mainnet": NetMagicMainnet,
		"testnet": NetMagicTestnet,
		"signet":  NetMagicSignet,
		"regtest": NetMagicRegtest,
	}
)

func startProxyListener(name string, addr string, peer string, netMagic []byte, v1ProtoOnly bool, v2ProtoOnly bool, metricsInclPeerInfo bool) {
	laddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to resolve address: %s", err)
	}

	listener, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		log.Fatal("Error starting proxy server:", err)
	}
	defer listener.Close()

	log.Printf("%s listening on %s", name, addr)

	conId := 0
	for {
		clientConn, err := listener.AcceptTCP()
		if err != nil {
			log.Println("Error accepting connection:", err)
			continue
		}
		metricProxyConnectionsIn.WithLabelValues().Inc()

		conId += 1
		con := ConnectionHandler{
			useRemoteAddr:   peer,
			conId:           conId,
			connLocal:       clientConn,
			v1ProtocolOnly:  v1ProtoOnly,
			v2ProtocolOnly:  v2ProtoOnly,
			metricsInclPeer: metricsInclPeerInfo,
			netMagic:        netMagic,
		}

		go con.handleLocalConnection()
	}
}

func main() {
	flagNetwork := flag.String("network", "mainnet", "the bitcoin network to use, options: mainnet, testnet, signet, regtest")
	flagProxyAddr := flag.String("addr", "127.0.0.1:38333", "proxy addr for listen for v1 messages")
	flagMetricsAddr := flag.String("metrics-addr", "127.0.0.1:9333", "http addr for expose prometheus metrics")
	flagMetricsInclPeerInfo := flag.Bool("metrics-incl-peer-info", false, "metrics-incl-peer-info")

	flagV1ProtocolOnly := flag.Bool("v1-only", false, "only v1 pass-through, do not try v2 connection with remote host")
	flagV2ProtocolOnly := flag.Bool("v2-only", false, "only use v2, no fallback to v1")

	flagPeersList := flag.String("peers", "", "use this list of peers only")
	flagPeersAddr := flag.String("peers-listen-addr", "127.0.0.1", "peers-listen-addr")
	flagPeersPort := flag.Int("peers-listen-port", 38400, "peers-listen-port")

	flag.Parse()

	nm, found := NetMagics[*flagNetwork]
	if !found {
		log.Println("invalid network")
		return
	}

	if flagMetricsAddr != nil && *flagMetricsAddr != "" {
		initMetrics(*flagMetricsInclPeerInfo)
		go func() {
			log.Printf("metrics listen addr: %s", *flagMetricsAddr)
			http.Handle("/metrics", promhttp.Handler())
			log.Fatal(http.ListenAndServe(*flagMetricsAddr, nil))
		}()
	}

	peers := strings.Split(*flagPeersList, ",")
	if len(peers) > 0 && *flagPeersAddr != "" && *flagPeersPort > 0 {
		port := *flagPeersPort
		for _, peer := range peers {
			peer = strings.TrimSpace(peer)
			if len(peer) > 0 {
				addr := fmt.Sprintf("%s:%d", *flagPeersAddr, port)
				port += 1
				name := fmt.Sprintf("Direct proxy to %s", peer)
				go func(a string) {
					startProxyListener(name, a, peer, nm, *flagV1ProtocolOnly, *flagV2ProtocolOnly, *flagMetricsInclPeerInfo)
				}(addr)
			}
		}
	}

	startProxyListener("Proxy server", *flagProxyAddr, "", nm, *flagV1ProtocolOnly, *flagV2ProtocolOnly, *flagMetricsInclPeerInfo)
}
