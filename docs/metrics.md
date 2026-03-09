# Prometheus Metrics

kube-federated-auth exposes Prometheus metrics at `GET /metrics`.

## Metrics Reference

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kfa_http_requests_total` | Counter | `method`, `path`, `status` | Total HTTP requests handled, by endpoint and status code |
| `kfa_http_request_duration_seconds` | Histogram | `method`, `path` | HTTP request latency in seconds, by endpoint |
| `kfa_cache_requests_total` | Counter | `cluster`, `result` | TokenReview cache lookups (hit/miss) per cluster |
| `kfa_cache_entries` | Gauge | `cluster` | Current number of cached TokenReview responses per cluster |
| `kfa_cluster_degraded` | Gauge | `cluster` | Whether a cluster's OIDC verifier is in a degraded state (1=degraded, 0=healthy) |
| `kfa_credential_renewal_total` | Counter | `cluster`, `result` | Credential renewal attempts per cluster (success/failure) |
| `kfa_credential_expiry_seconds` | Gauge | `cluster` | Seconds until the current credential expires for each cluster |
| `kfa_server_info` | Gauge | `version` | Server build version info (always 1) |

## Example Queries

```promql
# TokenReview request rate
rate(kfa_http_requests_total{path="/apis/authentication.k8s.io/v1/tokenreviews"}[5m])

# TokenReview p95 latency
histogram_quantile(0.95, rate(kfa_http_request_duration_seconds_bucket{path="/apis/authentication.k8s.io/v1/tokenreviews"}[5m]))

# Cache hit ratio per cluster
sum by (cluster) (rate(kfa_cache_requests_total{result="hit"}[5m]))
/
sum by (cluster) (rate(kfa_cache_requests_total[5m]))

# Degraded clusters
kfa_cluster_degraded == 1

# Credential expiry (hours remaining)
kfa_credential_expiry_seconds / 3600
```
