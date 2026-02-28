#!/bin/bash
# Performance test runner for kube-federated-auth
# Runs k6 as a Kubernetes Job inside the Kind cluster.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KUBE_CONTEXT="${KUBE_CONTEXT:-kind-cluster-a}"
KUBE_CONTEXT_B="${KUBE_CONTEXT_B:-kind-cluster-b}"
NAMESPACE="${NAMESPACE:-kube-federated-auth}"
SCENARIO="${1:-all}"
K6_IMAGE="${K6_IMAGE:-grafana/k6:latest}"
JOB_NAME="k6-perf-test"
CONFIGMAP_NAME="k6-perf-scripts"
CONFIGMAP_BACKUP=""

ka() {
  kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" "$@"
}

# --- ConfigMap management ---

save_configmap() {
  CONFIGMAP_BACKUP=$(mktemp)
  ka get configmap kube-federated-auth -o jsonpath='{.data.clusters\.yaml}' > "$CONFIGMAP_BACKUP"
}

restore_configmap() {
  [[ -n "$CONFIGMAP_BACKUP" && -f "$CONFIGMAP_BACKUP" ]] || return 0
  echo "Restoring ConfigMap..."
  ka create configmap kube-federated-auth \
    --from-file="clusters.yaml=${CONFIGMAP_BACKUP}" --dry-run=client -o yaml | ka apply -f -
  restart_and_wait
  rm -f "$CONFIGMAP_BACKUP"
  CONFIGMAP_BACKUP=""
}

disable_cache() {
  echo "Disabling cache..."
  local current
  current=$(ka get configmap kube-federated-auth -o jsonpath='{.data.clusters\.yaml}')
  local patched
  patched=$(echo "$current" | sed 's/ttl: [0-9]*/ttl: 0/')
  ka create configmap kube-federated-auth \
    --from-file=clusters.yaml=<(echo "$patched") --dry-run=client -o yaml | ka apply -f -
  restart_and_wait
}

restart_and_wait() {
  ka rollout restart deployment/kube-federated-auth
  ka rollout status deployment/kube-federated-auth --timeout=120s
  wait_for_health
  wait_for_tokenreview
}

wait_for_health() {
  echo "Waiting for service..."
  for i in $(seq 1 30); do
    if ka exec deployment/test-client -- \
      curl -sf http://kube-federated-auth/health >/dev/null 2>&1; then
      echo "Service is ready."
      return 0
    fi
    if [ "$i" -eq 30 ]; then
      echo "ERROR: service not ready after 30s" >&2
      exit 1
    fi
    sleep 1
  done
}

wait_for_tokenreview() {
  echo "Warming up OIDC verifier..."
  local token
  token=$(ka exec deployment/test-client -- cat /var/run/secrets/tokens/token 2>/dev/null) || true
  local caller_token
  caller_token=$(ka exec deployment/test-client -- \
    cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null) || true
  for i in $(seq 1 30); do
    local result
    result=$(ka exec deployment/test-client -- curl -s -X POST \
      http://kube-federated-auth/apis/authentication.k8s.io/v1/tokenreviews \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer ${caller_token}" \
      -d "{\"apiVersion\":\"authentication.k8s.io/v1\",\"kind\":\"TokenReview\",\"spec\":{\"token\":\"${token}\"}}" 2>/dev/null) || true
    if echo "$result" | grep -q '"authenticated":true' 2>/dev/null; then
      echo "TokenReview is ready."
      return 0
    fi
    sleep 1
  done
  echo "ERROR: TokenReview not ready after 30s" >&2
  exit 1
}

# --- Preflight checks ---

if ! kubectl --context "$KUBE_CONTEXT" cluster-info &>/dev/null; then
  echo "ERROR: kubectl context '$KUBE_CONTEXT' not reachable."
  echo "Run 'make deploy' to set up Kind clusters."
  exit 1
fi

if ! kubectl --context "$KUBE_CONTEXT_B" cluster-info &>/dev/null; then
  echo "ERROR: kubectl context '$KUBE_CONTEXT_B' not reachable."
  echo "Run 'make deploy' to set up Kind clusters."
  exit 1
fi

# --- Cleanup from previous runs ---

cleanup() {
  echo "Cleaning up..."
  ka delete job "$JOB_NAME" --ignore-not-found >/dev/null 2>&1
  ka delete configmap "$CONFIGMAP_NAME" --ignore-not-found >/dev/null 2>&1
  restore_configmap
}
trap cleanup EXIT

cleanup

# --- Save ConfigMap for restore ---

save_configmap

# --- Create ConfigMap from JS files ---

echo "Creating ConfigMap with k6 scripts..."
ka create configmap "$CONFIGMAP_NAME" \
  --from-file="$SCRIPT_DIR/lib/helpers.js" \
  --from-file="$SCRIPT_DIR/scenarios/health.js" \
  --from-file="$SCRIPT_DIR/scenarios/tokenreview.js" \
  --from-file="$SCRIPT_DIR/scenarios/tokenreview-cached.js"

# --- Generate tokens ---

echo "Generating tokens..."
CALLER_TOKEN=$(kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" \
  create token test-client --duration=10m)
REVIEW_TOKEN_A=$(kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" \
  create token test-client --duration=10m)
REVIEW_TOKEN_B=$(kubectl --context "$KUBE_CONTEXT_B" -n "$NAMESPACE" \
  create token kube-federated-auth-reader --duration=10m)

# --- Run a k6 scenario as a Job ---

run_scenario() {
  local name="$1"
  echo ""
  echo "=== Running: ${name} ==="

  # Clean previous job
  ka delete job "$JOB_NAME" --ignore-not-found >/dev/null 2>&1
  ka wait --for=delete job/"$JOB_NAME" --timeout=30s 2>/dev/null || true

  ka apply -f - <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: ${JOB_NAME}
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      containers:
      - name: k6
        image: ${K6_IMAGE}
        command: ["k6", "run", "/scripts/scenarios/${name}.js"]
        env:
        - name: BASE_URL
          value: "kube-federated-auth"
        - name: CALLER_TOKEN
          value: "${CALLER_TOKEN}"
        - name: REVIEW_TOKEN_A
          value: "${REVIEW_TOKEN_A}"
        - name: REVIEW_TOKEN_B
          value: "${REVIEW_TOKEN_B}"
        volumeMounts:
        - name: scripts
          mountPath: /scripts/scenarios
        - name: lib
          mountPath: /scripts/lib
      volumes:
      - name: scripts
        configMap:
          name: ${CONFIGMAP_NAME}
          items:
          - key: health.js
            path: health.js
          - key: tokenreview.js
            path: tokenreview.js
          - key: tokenreview-cached.js
            path: tokenreview-cached.js
      - name: lib
        configMap:
          name: ${CONFIGMAP_NAME}
          items:
          - key: helpers.js
            path: helpers.js
EOF

  # Wait for pod to start, then stream logs
  echo "Waiting for k6 pod to start..."
  ka wait --for=condition=ready pod -l job-name="$JOB_NAME" --timeout=120s 2>/dev/null || true

  # Stream logs (follows until container exits)
  ka logs -f job/"$JOB_NAME" 2>/dev/null || true

  # Check job result
  if ka wait --for=condition=complete job/"$JOB_NAME" --timeout=10s &>/dev/null; then
    echo "=== ${name}: PASSED ==="
  else
    echo "=== ${name}: FAILED ==="
    return 1
  fi
}

# --- Main ---

case "$SCENARIO" in
  all)
    run_scenario health
    disable_cache
    run_scenario tokenreview
    restore_configmap
    save_configmap
    run_scenario tokenreview-cached
    ;;
  health)
    run_scenario health
    ;;
  tokenreview)
    disable_cache
    run_scenario tokenreview
    ;;
  tokenreview-cached)
    run_scenario tokenreview-cached
    ;;
  *)
    echo "Usage: $0 [health|tokenreview|tokenreview-cached|all]"
    exit 1
    ;;
esac

echo ""
echo "=== Performance tests complete ==="
