package main

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	apiSentRequestsMetrics = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "knet_stress",
			Subsystem: "client",
			Name:      "api_requests_sent",
			Help:      "Number of requests sent to the API server",
		},

		[]string{"instance_id", "code"},
	)

	durationMetrics = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "knet_stress",
			Subsystem: "client",
			Name:      "requests_duration_seconds",
			Help:      "Duration of network requests in seconds",
			Buckets:   prometheus.LinearBuckets(.000, .005, 40),
		},
		[]string{"instance_id", "code"},
	)

	sentRequestMetrics = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "knet_stress",
			Subsystem: "client",
			Name:      "requests_sent",
			Help:      "Number of requests sent",
		},

		[]string{"instance_id", "code"},
	)

	receivedRequestMetrics = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "knet_stress",
			Subsystem: "server",
			Name:      "requests_received",
			Help:      "Number of requests received",
		},

		[]string{"instance_id"},
	)
)

func init() {
	prometheus.MustRegister(apiSentRequestsMetrics)
	prometheus.MustRegister(durationMetrics)
	prometheus.MustRegister(sentRequestMetrics)
	prometheus.MustRegister(receivedRequestMetrics)
}
