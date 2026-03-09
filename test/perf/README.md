# Performance Tests

Load tests using [k6](https://k6.io/) run as a Kubernetes Job inside the Kind cluster.

## Usage

```bash
# Run all scenarios
make test-perf
# or: bash test/perf/run.sh all

# Run a specific scenario
bash test/perf/run.sh health
bash test/perf/run.sh tokenreview
bash test/perf/run.sh tokenreview-cached
```

**Prerequisites:** Both Kind clusters must be running with the app deployed (`make deploy`).

## Scenarios

| Scenario | Description | Thresholds |
|----------|-------------|------------|
| `health` | Constant 100 req/s for 30s against `/health` | p95 < 50ms, p99 < 100ms |
| `tokenreview` | Ramping VUs (1→10→0) over 40s, cache disabled | p95 < 2s, p99 < 3s |
| `tokenreview-cached` | Warmup + 50 req/s sustained for 20s, cache enabled | p95 < 100ms, p99 < 200ms |

## How It Works

1. Checks both Kind clusters are reachable
2. Creates a ConfigMap with the k6 scripts
3. Generates short-lived tokens (caller + review tokens from both clusters)
4. Runs each scenario as a k6 Job inside the cluster
5. Restores the original ConfigMap on exit

For `tokenreview`, the runner temporarily sets `cache.ttl: 0` to disable the application-level cache, then restores the original config afterward.

## Files

- `run.sh` — Test runner (ConfigMap setup, token generation, Job lifecycle)
- `lib/helpers.js` — Shared helpers (TokenReview payload builder, assertions)
- `scenarios/health.js` — Health endpoint baseline
- `scenarios/tokenreview.js` — Uncached TokenReview with ramp-up
- `scenarios/tokenreview-cached.js` — Cached TokenReview at sustained rate

## Understanding the Results

### Why `tokenreview` (uncached) latency is high

The uncached scenario shows ~500ms average latency even on local Kind clusters. This is **not** network latency — it's caused by `client-go`'s default rate limiter (5 QPS / 10 burst).

Each uncached request makes two K8s API calls:
1. Caller authentication (JWKS verify via `go-oidc`'s `RemoteKeySet`)
2. TokenReview forwarding to the target cluster's API server

With 10 VUs generating requests faster than the 5 QPS budget, requests queue behind the rate limiter. Configure `qps` and `burst` per cluster to increase throughput:

```yaml
clusters:
  cluster-b:
    qps: 50
    burst: 100
```

### Cached vs uncached

The cache stores full `TokenReview` responses keyed by `sha256(cluster + token)`. Cache hits skip the TokenReview forwarding entirely, reducing latency from ~500ms to ~1ms.
