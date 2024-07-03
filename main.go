package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
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
	   Testnet: 0x0709110B
	   Signet:  0x40CF030A
	   Regtest: 0xDAB5BFFA
	*/
	NetMagicSignet wire.BitcoinNet = 0x40CF030A
	btcNetworkMap                  = map[string]wire.BitcoinNet{
		"mainnet": wire.MainNet,
		"testnet": wire.TestNet3,
		"signet":  NetMagicSignet,
		"regtest": wire.TestNet,
	}
)

func startProxyListener(name string, addr string, peer string, btcNet wire.BitcoinNet, v1ProtoOnly bool, v2ProtoOnly bool, metricsInclPeerInfo bool) {
	laddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to resolve address")
	}

	listener, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		log.Fatal().Err(err).Msg("Error starting proxy server")

	}
	defer listener.Close()

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
		)

		go con.handleLocalConnection()
	}
}

func main() {
	flagDebugLogLevel := flag.Bool("debug", false, "set log level to debug")
	flagTraceLogLevel := flag.Bool("trace", false, "set log level to trace")

	flagNetwork := flag.String("network", "mainnet", "the bitcoin network to use, options: mainnet, testnet, signet, regtest")
	flagProxyAddr := flag.String("addr", "127.0.0.1:8324", "local proxy addr for listen for v1 messages")
	flagMetricsAddr := flag.String("metrics-addr", "127.0.0.1:9333", "http addr for expose prometheus metrics")
	flagMetricsInclPeerInfo := flag.Bool("metrics-incl-peer-info", false, "metrics-incl-peer-info")

	flagV1ProtocolOnly := flag.Bool("v1-only", false, "only v1 pass-through, do not try v2 connection with remote host")
	flagV2ProtocolOnly := flag.Bool("v2-only", false, "only use v2, no fallback to v1")

	flagPeersList := flag.String("peers", "", "use this list of peers only")
	flagPeersAddr := flag.String("peers-listen-addr", "127.0.0.1", "peers-listen-addr")
	flagPeersPort := flag.Int("peers-listen-port", 38400, "peers-listen-port")

	flag.Parse()

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
		log.Info().Msgf("invalid network: %s", *flagNetwork)
		return
	}

	if flagMetricsAddr != nil && *flagMetricsAddr != "" {
		initMetrics(*flagMetricsInclPeerInfo)
		go func() {
			log.Info().Msgf("metrics listen addr: %s", *flagMetricsAddr)
			http.Handle("/metrics", promhttp.Handler())
			if err := http.ListenAndServe(*flagMetricsAddr, nil); err != nil {
				log.Fatal().Err(err).Msg("http.ListenAndServe")
			}
		}()
	}

	peers := strings.Split(*flagPeersList, ",")
	if len(peers) > 0 && *flagPeersAddr != "" && *flagPeersPort > 0 {
		port := *flagPeersPort
		for _, peer := range peers {
			peer = strings.TrimSpace(peer)
			if len(peer) > 0 {
				addr := fmt.Sprintf("%s:%d", *flagPeersAddr, port)
				name := fmt.Sprintf("direct proxy to %s", peer)
				go func(a string, p string) {
					startProxyListener(name, a, p, btcNet, *flagV1ProtocolOnly, *flagV2ProtocolOnly, *flagMetricsInclPeerInfo)
				}(addr, peer)

				port += 1
				time.Sleep(100 * time.Millisecond)
			}
		}
	}

	startProxyListener("proxy server", *flagProxyAddr, "", btcNet, *flagV1ProtocolOnly, *flagV2ProtocolOnly, *flagMetricsInclPeerInfo)
}
