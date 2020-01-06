package main

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	latencyMetrics = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "knet_stress",
			Subsystem: "client",
			Name:      "request_latency",
			Help:      "Latency of network requests",
		},

		[]string{"instance_id"},
	)

	sentRequestMetrics = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "knet_stress",
			Subsystem: "client",
			Name:      "request_sent_count",
			Help:      "Number of requests sent",
		},

		[]string{"instance_id"},
	)

	receivedRequestMetrics = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "knet_stress",
			Subsystem: "server",
			Name:      "request_received_count",
			Help:      "Number of requests received",
		},

		[]string{"instance_id"},
	)
)

func init() {
	prometheus.MustRegister(latencyMetrics)
	prometheus.MustRegister(sentRequestMetrics)
	prometheus.MustRegister(receivedRequestMetrics)
}
