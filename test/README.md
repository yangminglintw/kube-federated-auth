# Tests

## Unit Tests

Standard Go tests colocated with source code in `internal/` packages.

```bash
make test-unit
# or: go test -v ./internal/...
```

Packages with tests:
- `internal/config` — config parsing and defaults
- `internal/credentials` — credential store and renewal logic
- `internal/handler` — HTTP handler request/response
- `internal/oidc` — OIDC/JWKS token verification
- `internal/cache` — generic cache

## E2E Tests

Integration tests using [bats](https://github.com/bats-core/bats-core) that run against live Kind clusters (`kind-cluster-a` and `kind-cluster-b`).

```bash
make test-e2e
# or: bats test/e2e/
```

**Prerequisites:** Both Kind clusters must be running with the app deployed (`make deploy`).

Test files:
- `e2e/e2e.bats` — core functionality: health, clusters endpoint, TokenReview for valid/invalid/cross-cluster tokens, caller authorization (401/403)
- `e2e/cache.bats` — verifies TokenReview cache hit behavior via server logs
- `e2e/no-token-path.bats` — token loading from Secret when `token_path` is not configured

Tests run on the host and use `kubectl exec` to reach in-cluster services. Common helpers are in `e2e/test_helper.bash`.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KUBE_CONTEXT` | `kind-cluster-a` | kubectl context for the main cluster |
| `KUBE_CONTEXT_B` | `kind-cluster-b` | kubectl context for the remote cluster |
| `NAMESPACE` | `kube-federated-auth` | Namespace for main cluster resources |
| `SERVICE_URL` | `http://kube-federated-auth` | In-cluster service URL |

## Performance Tests

Load tests using [k6](https://k6.io/) run as a Kubernetes Job inside the Kind cluster.

```bash
make test-perf
# or: bash test/perf/run.sh [scenario]
```

**Prerequisites:** Same as e2e — both Kind clusters running with the app deployed.

### Scenarios

Run a specific scenario or `all` (default):

```bash
bash test/perf/run.sh health
bash test/perf/run.sh tokenreview
bash test/perf/run.sh tokenreview-cached
bash test/perf/run.sh all
```

| Scenario | Description | Thresholds |
|----------|-------------|------------|
| `health` | Constant 100 req/s for 30s against `/health` | p95 < 50ms, p99 < 100ms |
| `tokenreview` | Ramping VUs (1→10→0) with cache disabled | p95 < 2s, p99 < 3s |
| `tokenreview-cached` | Warmup + 50 req/s sustained with cache enabled | p95 < 100ms, p99 < 200ms |

The `tokenreview` scenario temporarily disables the cache to test full OIDC verification. The original config is restored after each run.
