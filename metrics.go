package main

import "github.com/prometheus/client_golang/prometheus"

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
)

func initMetrics(metricsInclPeerInfo bool) {

	lbls := []string{"version", "type", "direction"}
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

	// node_network_transmit_bytes_total

	prometheus.MustRegister(metricProxyConnectionsIn)
	prometheus.MustRegister(metricProxyConnectionsOut)
	prometheus.MustRegister(metricProxyConnectionsOutErrors)
	prometheus.MustRegister(metricProxyConnectionsV1Fallbacks)
	prometheus.MustRegister(metricMessagesReceived)
	prometheus.MustRegister(metricMessagesSent)
	prometheus.MustRegister(metricBytesSent)
	prometheus.MustRegister(metricBytesReceived)
}

func (c *ConnectionHandler) metricMsgReceived(v string, t string, dir string) {
	lbls := prometheus.Labels{
		"direction": dir,
		"type":      t,
		"version":   v,
	}
	if c.metricsInclPeer {
		lbls["peer"] = c.peerRemoteAddr
	}
	metricMessagesReceived.With(lbls).Inc()
}

func (c *ConnectionHandler) metricMsgSent(v string, t string, dir string) {
	lbls := prometheus.Labels{
		"direction": dir,
		"type":      t,
		"version":   v,
	}
	if c.metricsInclPeer {
		lbls["peer"] = c.peerRemoteAddr
	}
	metricMessagesSent.With(lbls).Inc()
}
