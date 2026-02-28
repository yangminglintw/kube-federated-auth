#!/usr/bin/env bats
# Tests token loading from Secret when token_path is not configured.
# Simulates the scenario where token is pre-loaded in Secret (e.g., from a previous run)
# and ca_cert is loaded from mounted file.

ORIGINAL_CM=""

setup() {
    load 'test_helper'

    # Save original configmap (strip resourceVersion to avoid conflicts on restore)
    ORIGINAL_CM=$(mktemp)
    ka get configmap kube-federated-auth -o json \
        | jq 'del(.metadata.resourceVersion)' > "$ORIGINAL_CM"

    # Patch configmap: remove token_path for cluster-b
    ka get configmap kube-federated-auth -o json \
        | jq 'del(.metadata.resourceVersion) | .data["clusters.yaml"] |= gsub("\\s+token_path: \"/etc/kube-federated-auth/tokens/cluster-b-token\""; "")' \
        | ka apply -f -

    # Delete existing secret
    ka delete secret kube-federated-auth --ignore-not-found
}

teardown() {
    load 'test_helper'

    # Restore original configmap
    if [[ -n "$ORIGINAL_CM" && -f "$ORIGINAL_CM" ]]; then
        ka apply -f "$ORIGINAL_CM"
        rm -f "$ORIGINAL_CM"
    fi

    # Recreate secret with a fresh bootstrap token so the restored config works
    ka delete secret kube-federated-auth --ignore-not-found
    local bootstrap_token
    bootstrap_token=$(kubectl --context "$KUBE_CONTEXT_B" -n "$NAMESPACE_B" \
        create token kube-federated-auth-reader --duration=10m)
    ka create secret generic kube-federated-auth \
        --from-literal="cluster-b-token=${bootstrap_token}"

    # Rollout restart to restore original state
    ka rollout restart deployment/kube-federated-auth
    ka rollout status deployment/kube-federated-auth --timeout=60s
    wait_for_service
    wait_for_tokenreview
}

@test "TokenReview works with token from Secret and no token_path" {
    # 1. Create a cluster-b token and put it in the Secret
    local seed_token
    seed_token=$(kubectl --context "$KUBE_CONTEXT_B" -n "$NAMESPACE_B" \
        create token kube-federated-auth-reader --duration=10m)

    ka create secret generic kube-federated-auth \
        --from-literal="cluster-b-token=${seed_token}"

    # 2. Rollout restart and wait for full readiness
    ka rollout restart deployment/kube-federated-auth
    ka rollout status deployment/kube-federated-auth --timeout=60s
    wait_for_service
    wait_for_tokenreview

    # Give the renewal loop time to complete (runs in background goroutine)
    sleep 2

    # 3. Check logs
    local logs
    logs=$(server_logs)

    echo "# --- Server logs ---"
    echo "$logs"

    # Token loaded from Secret
    echo "$logs" | grep -q "loaded token from secret.*cluster-b"

    # CA cert loaded from file
    echo "$logs" | grep -q "loaded CA cert from file.*cluster-b"

    # No bootstrap token loaded from file for cluster-b
    if echo "$logs" | grep -q "loaded bootstrap token from file.*cluster-b"; then
        echo "# FAIL: bootstrap token should not be loaded from file"
        return 1
    fi

    # Token renewal succeeded
    echo "$logs" | grep -q "successfully renewed credentials.*cluster-b"

    # 4. Verify Secret has a renewed token (different from seed)
    local secret_token
    secret_token=$(ka get secret kube-federated-auth -o jsonpath='{.data.cluster-b-token}' | base64 -d)

    if [[ "$secret_token" == "$seed_token" ]]; then
        echo "# FAIL: token in Secret should have been renewed"
        return 1
    fi
    echo "# Token was renewed (Secret updated)"

    # 5. Call TokenReview API to verify end-to-end
    local review_token
    review_token=$(get_cluster_b_token)

    local result
    result=$(token_review "$review_token")

    echo "# TokenReview response: $result"

    local authenticated
    authenticated=$(echo "$result" | jq -r '.status.authenticated')
    [[ "$authenticated" == "true" ]]

    local clusterExtra
    clusterExtra=$(echo "$result" | jq -r '.status.user.extra["authentication.kubernetes.io/cluster-name"][0]')
    [[ "$clusterExtra" == "cluster-b" ]]
}
