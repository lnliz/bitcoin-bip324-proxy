package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	/*
		   Mainnet: 0xD9B4BEF9
			   Testnet3: 0x0709110B
			   Testnet4: 0x283F161C
			   Signet:   0x40CF030A
			   Regtest:  0xDAB5BFFA
	*/
	btcNetworkMap = map[string]wire.BitcoinNet{
		"mainnet":  wire.MainNet,
		"testnet":  wire.TestNet3,
		"testnet3": wire.TestNet3,
		"testnet4": wire.TestNet4,
		"signet":   wire.SigNet,
		"regtest":  wire.TestNet,
	}
)

func parsePeers(value string) []string {
	var peers []string
	for _, peer := range strings.Split(value, ",") {
		if peer = strings.TrimSpace(peer); peer != "" {
			peers = append(peers, peer)
		}
	}
	return peers
}

func startProxyListener(name string, addr string, peer string, btcNet wire.BitcoinNet, v1ProtoOnly bool, v2ProtoOnly bool, metricsInclPeerInfo bool, appendUserAgentString bool) {
	laddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to resolve address")
	}

	listener, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		log.Fatal().Err(err).Msg("Error starting proxy server")

	}
	defer func() { _ = listener.Close() }()

	log.Info().Msgf("Listening on %s as %s", addr, name)

	for {
		clientConn, err := listener.AcceptTCP()
		if err != nil {
			log.Info().Msgf("Error accepting connection: %s", err)
			continue
		}
		metricProxyConnectionsIn.WithLabelValues().Inc()

		con := NewConnectionHandler(
			btcNet,
			peer,
			clientConn,
			v1ProtoOnly,
			v2ProtoOnly,
			metricsInclPeerInfo,
			appendUserAgentString,
		)

		go con.handleLocalConnection()
	}
}

func main() {
	flagDebugLogLevel := flag.Bool("debug", false, "set log level to debug")
	flagTraceLogLevel := flag.Bool("trace", false, "set log level to trace")

	flagNetwork := flag.String("network", "mainnet", "the bitcoin network to use, options: mainnet, testnet, testnet3, testnet4, signet, regtest")
	flagProxyAddr := flag.String("addr", "127.0.0.1:8324", "local proxy addr for listen for v1 messages")
	flagMetricsAddr := flag.String("metrics-addr", "127.0.0.1:9333", "http addr for expose prometheus metrics")
	flagMetricsInclPeerInfo := flag.Bool("metrics-incl-peer-info", false, "metrics-incl-peer-info")
	flagAppendUserAgent := flag.Bool("append-proxy-user-agent", false, `add "bip324-proxy" to user agent`)

	flagV1ProtocolOnly := flag.Bool("v1-only", false, "only v1 pass-through, do not try v2 connection with remote host")
	flagV2ProtocolOnly := flag.Bool("v2-only", false, "only use v2, no fallback to v1")

	flagPeersList := flag.String("peers", "", "use this list of peers only")
	flagPeersAddr := flag.String("peers-listen-addr", "127.0.0.1", "peers-listen-addr")
	flagPeersPort := flag.Int("peers-listen-port", 38400, "peers-listen-port")

	flag.Parse()
	if *flagV1ProtocolOnly && *flagV2ProtocolOnly {
		log.Fatal().Msg("--v1-only and --v2-only cannot be used together")
	}

	// Default level for this example is info, unless flagDebugLogLevel flag is present
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if *flagDebugLogLevel {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	if *flagTraceLogLevel {
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	}

	btcNet, found := btcNetworkMap[*flagNetwork]
	if !found {
		log.Fatal().Msgf("invalid network: %s", *flagNetwork)
	}

	initMetrics(*flagMetricsInclPeerInfo)
	if *flagMetricsAddr != "" {
		go func() {
			log.Info().Msgf("metrics listen addr: %s", *flagMetricsAddr)
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.Handler())
			server := &http.Server{
				Addr:              *flagMetricsAddr,
				Handler:           mux,
				ReadHeaderTimeout: 5 * time.Second,
			}
			if err := server.ListenAndServe(); err != nil {
				log.Fatal().Err(err).Msg("metrics server")
			}
		}()
	}

	peers := parsePeers(*flagPeersList)
	if len(peers) > 0 && *flagPeersAddr != "" {
		if *flagPeersPort <= 0 || *flagPeersPort > 65535 {
			log.Fatal().Msgf("invalid peers listen port: %d", *flagPeersPort)
		}
		if len(peers)-1 > 65535-*flagPeersPort {
			log.Fatal().Msgf("peer listeners starting at %d exceed port 65535", *flagPeersPort)
		}
		port := *flagPeersPort
		for _, peer := range peers {
			peer = strings.TrimSpace(peer)
			if len(peer) > 0 {
				addr := net.JoinHostPort(*flagPeersAddr, strconv.Itoa(port))
				name := fmt.Sprintf("direct proxy to %s", peer)
				go startProxyListener(name, addr, peer, btcNet, *flagV1ProtocolOnly, *flagV2ProtocolOnly, *flagMetricsInclPeerInfo, *flagAppendUserAgent)

				port += 1
			}
		}
	}

	startProxyListener("proxy server", *flagProxyAddr, "", btcNet, *flagV1ProtocolOnly, *flagV2ProtocolOnly, *flagMetricsInclPeerInfo, *flagAppendUserAgent)
}
