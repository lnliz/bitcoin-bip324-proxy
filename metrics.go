package main

import (
	"sync"

	"github.com/btcsuite/btcd/wire"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	namespace = "bip324_proxy"

	metricProxyConnectionsIn = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   namespace,
		Name:        "connections_in",
		Help:        "connections_in",
		ConstLabels: nil,
	}, nil)

	metricProxyConnectionsOut = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   namespace,
		Name:        "connections_out",
		Help:        "connections_out",
		ConstLabels: nil,
	}, []string{"version"})

	metricProxyConnectionsOutErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   namespace,
		Name:        "connections_out_errors",
		Help:        "connections_out_errors",
		ConstLabels: nil,
	}, []string{"version"})

	metricProxyConnectionsV1Fallbacks *prometheus.CounterVec
	metricMessagesReceived            *prometheus.CounterVec
	metricMessagesSent                *prometheus.CounterVec
	metricBytesSent                   *prometheus.CounterVec
	metricBytesReceived               *prometheus.CounterVec
	metricsOnce                       sync.Once
	metricsIncludePeerLabel           bool
	metricKnownCommands               = map[string]struct{}{
		wire.CmdVersion: {}, wire.CmdVerAck: {}, wire.CmdGetAddr: {},
		wire.CmdAddr: {}, wire.CmdAddrV2: {}, wire.CmdGetBlocks: {},
		wire.CmdInv: {}, wire.CmdGetData: {}, wire.CmdNotFound: {},
		wire.CmdBlock: {}, wire.CmdTx: {}, wire.CmdGetHeaders: {},
		wire.CmdHeaders: {}, wire.CmdPing: {}, wire.CmdPong: {},
		wire.CmdMemPool: {}, wire.CmdFilterAdd: {}, wire.CmdFilterClear: {},
		wire.CmdFilterLoad: {}, wire.CmdMerkleBlock: {}, wire.CmdReject: {},
		wire.CmdSendHeaders: {}, wire.CmdFeeFilter: {}, wire.CmdGetCFilters: {},
		wire.CmdGetCFHeaders: {}, wire.CmdGetCFCheckpt: {}, wire.CmdCFilter: {},
		wire.CmdCFHeaders: {}, wire.CmdCFCheckpt: {}, wire.CmdSendAddrV2: {},
		wire.CmdWTxIdRelay: {},
		"blocktxn":         {}, "cmpctblock": {}, "getblocktxn": {}, "sendcmpct": {},
		"uproof": {}, "getuproof": {}, "uttls": {}, "getuttls": {},
		"usummary": {}, "utreexotx": {}, "uroot": {}, "geturoot": {},
		"feature": {},
	}
)

func initMetrics(metricsInclPeerInfo bool) {
	metricsOnce.Do(func() {
		initMetricsOnce(metricsInclPeerInfo)
	})
}

func initMetricsOnce(metricsInclPeerInfo bool) {
	metricsIncludePeerLabel = metricsInclPeerInfo
	lbls := []string{"version", "command", "interface"}
	if metricsInclPeerInfo {
		lbls = append(lbls, "peer")
	}

	metricProxyConnectionsIn = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   namespace,
		Name:        "connections_in",
		Help:        "connections_in",
		ConstLabels: nil,
	}, nil)

	metricProxyConnectionsV1Fallbacks = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   namespace,
		Name:        "connections_v1_fallbacks",
		Help:        "connections_v1_fallbacks",
		ConstLabels: nil,
	}, nil)

	metricMessagesReceived = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   namespace,
		Name:        "messages_received",
		Help:        "messages_received",
		ConstLabels: nil,
	}, lbls)

	metricMessagesSent = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   namespace,
		Name:        "messages_sent",
		Help:        "messages_sent",
		ConstLabels: nil,
	}, lbls)

	metricBytesReceived = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   namespace,
		Name:        "bytes_received_total",
		Help:        "bytes_received_total",
		ConstLabels: nil,
	}, lbls)

	metricBytesSent = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   namespace,
		Name:        "bytes_sent_total",
		Help:        "bytes_sent_total",
		ConstLabels: nil,
	}, lbls)

	prometheus.MustRegister(metricProxyConnectionsIn)
	prometheus.MustRegister(metricProxyConnectionsOut)
	prometheus.MustRegister(metricProxyConnectionsOutErrors)
	prometheus.MustRegister(metricProxyConnectionsV1Fallbacks)
	prometheus.MustRegister(metricMessagesReceived)
	prometheus.MustRegister(metricMessagesSent)
	prometheus.MustRegister(metricBytesSent)
	prometheus.MustRegister(metricBytesReceived)
}

func (c *ConnectionHandler) metricMsgReceived(v string, cmd string, iface string, payloadBytes int) {
	cmd = metricCommandLabel(cmd)
	c.log.Trace().Str("cmd", cmd).Str("version", v).Str("iface", iface).Msg("metricMsgReceived")
	lbls := prometheus.Labels{
		"version":   v,
		"command":   cmd,
		"interface": iface,
	}
	if c.metricsInclPeer {
		lbls["peer"] = c.peerRemoteAddr
	}
	metricMessagesReceived.With(lbls).Inc()
	metricBytesReceived.With(lbls).Add(float64(payloadBytes))
}

func (c *ConnectionHandler) metricMsgSent(v string, cmd string, iface string, payloadBytes int) {
	cmd = metricCommandLabel(cmd)
	c.log.Trace().Str("cmd", cmd).Str("version", v).Str("iface", iface).Msg("metricMsgSent")
	lbls := prometheus.Labels{
		"interface": iface,
		"command":   cmd,
		"version":   v,
	}
	if c.metricsInclPeer {
		lbls["peer"] = c.peerRemoteAddr
	}
	metricMessagesSent.With(lbls).Inc()
	metricBytesSent.With(lbls).Add(float64(payloadBytes))
}

func metricCommandLabel(command string) string {
	if _, known := metricKnownCommands[command]; known {
		return command
	}
	return "other"
}
