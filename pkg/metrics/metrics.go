package metrics

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type Metrics struct {
	instanceID string

	apiSentRequestsMetrics *prometheus.CounterVec
	durationMetrics        *prometheus.HistogramVec
	sentRequestMetrics     *prometheus.CounterVec
	receivedRequestMetrics *prometheus.CounterVec
}

func New(instanceID string) *Metrics {
	metrics := &Metrics{
		apiSentRequestsMetrics: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "knet_stress",
				Subsystem: "client",
				Name:      "api_requests_sent",
				Help:      "Number of requests sent to the API server",
			},

			[]string{"instance_id", "code"},
		),

		durationMetrics: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "knet_stress",
				Subsystem: "client",
				Name:      "requests_duration_seconds",
				Help:      "Duration of network requests in seconds",
				Buckets:   prometheus.LinearBuckets(.000, .005, 40),
			},
			[]string{"instance_id", "code"},
		),

		sentRequestMetrics: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "knet_stress",
				Subsystem: "client",
				Name:      "requests_sent",
				Help:      "Number of requests sent",
			},

			[]string{"instance_id", "code"},
		),

		receivedRequestMetrics: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "knet_stress",
				Subsystem: "server",
				Name:      "requests_received",
				Help:      "Number of requests received",
			},

			[]string{"instance_id"},
		),
	}

	prometheus.MustRegister(metrics.apiSentRequestsMetrics)
	prometheus.MustRegister(metrics.durationMetrics)
	prometheus.MustRegister(metrics.sentRequestMetrics)
	prometheus.MustRegister(metrics.receivedRequestMetrics)

	return metrics
}

func (m *Metrics) APISentInc(statusCode int32) {
	m.apiSentRequestsMetrics.WithLabelValues(m.instanceID, strconv.FormatInt(int64(statusCode), 10)).Inc()
}

func (m *Metrics) DurationObserve(statusCode int, start time.Time) {
	m.durationMetrics.WithLabelValues(m.instanceID, strconv.Itoa(statusCode)).Observe(time.Since(start).Seconds())
}

func (m *Metrics) SentRequestInc(statusCode int) {
	m.sentRequestMetrics.WithLabelValues(m.instanceID, strconv.Itoa(statusCode)).Inc()
}

func (m *Metrics) ReceivedRequestInc() {
	m.receivedRequestMetrics.WithLabelValues(m.instanceID).Inc()
}
