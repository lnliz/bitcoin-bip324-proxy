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
	}, nil)

	metricProxyConnectionsV1Fallbacks *prometheus.CounterVec
	messagesReceived                  *prometheus.CounterVec
	messagesSent                      *prometheus.CounterVec
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

	messagesReceived = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   namespace,
		Name:        "messages_received",
		Help:        "messages_received",
		ConstLabels: nil,
	}, lbls)

	messagesSent = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   namespace,
		Name:        "messages_sent",
		Help:        "messages_sent",
		ConstLabels: nil,
	}, lbls)

	prometheus.MustRegister(metricProxyConnectionsIn)
	prometheus.MustRegister(messagesReceived)
	prometheus.MustRegister(messagesSent)
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
	messagesReceived.With(lbls).Inc()
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
	messagesSent.With(lbls).Inc()
}
