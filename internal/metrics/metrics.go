package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const namespace = "kfa"

// Metrics holds all Prometheus metrics for kube-federated-auth.
type Metrics struct {
	HTTPRequestsTotal       *prometheus.CounterVec
	HTTPRequestDuration     *prometheus.HistogramVec
	CacheRequestsTotal      *prometheus.CounterVec
	CacheEntries            *prometheus.GaugeVec
	ClusterDegraded         *prometheus.GaugeVec
	CredentialRenewalTotal  *prometheus.CounterVec
	CredentialExpirySeconds *prometheus.GaugeVec
	ServerInfo              *prometheus.GaugeVec
}

// New creates and registers all Prometheus metrics.
func New(version string) *Metrics {
	m := &Metrics{
		HTTPRequestsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "http_requests_total",
			Help:      "Total HTTP requests handled, by endpoint and status code.",
		}, []string{"method", "path", "status"}),

		HTTPRequestDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "http_request_duration_seconds",
			Help:      "HTTP request latency in seconds, by endpoint.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"method", "path"}),

		CacheRequestsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "cache_requests_total",
			Help:      "TokenReview cache lookups (hit/miss) per cluster.",
		}, []string{"cluster", "result"}),

		CacheEntries: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "cache_entries",
			Help:      "Current number of cached TokenReview responses per cluster.",
		}, []string{"cluster"}),

		ClusterDegraded: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "cluster_degraded",
			Help:      "Whether a cluster's OIDC verifier is in a degraded state (1=degraded, 0=healthy).",
		}, []string{"cluster"}),

		CredentialRenewalTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "credential_renewal_total",
			Help:      "Credential renewal attempts per cluster (success/failure).",
		}, []string{"cluster", "result"}),

		CredentialExpirySeconds: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "credential_expiry_seconds",
			Help:      "Seconds until the current credential expires for each cluster.",
		}, []string{"cluster"}),

		ServerInfo: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "server_info",
			Help:      "Server build version info (always 1).",
		}, []string{"version"}),
	}

	m.ServerInfo.WithLabelValues(version).Set(1)

	return m
}
