package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/rophy/kube-federated-auth/internal/cache"
	"github.com/rophy/kube-federated-auth/internal/config"
	"github.com/rophy/kube-federated-auth/internal/credentials"
	mw "github.com/rophy/kube-federated-auth/internal/middleware"
	"github.com/rophy/kube-federated-auth/internal/oidc"
)

// ExtraKeyClusterName is the key used in TokenReview response extra field
// to indicate which cluster the token was validated against.
const ExtraKeyClusterName = "authentication.kubernetes.io/cluster-name"

// TokenVerifier verifies tokens against a specific cluster's JWKS.
type TokenVerifier interface {
	Verify(ctx context.Context, clusterName, rawToken string) (*oidc.Claims, error)
}

type TokenReviewHandler struct {
	verifier       TokenVerifier
	config         *config.Config
	credStore      *credentials.Store
	statusProvider ClusterStatusProvider
	caches         map[string]*cache.Cache[*authv1.TokenReview]
	clients        map[string]kubernetes.Interface
	clientsMu      sync.RWMutex
}

func NewTokenReviewHandler(v TokenVerifier, cfg *config.Config, store *credentials.Store, sp ClusterStatusProvider) *TokenReviewHandler {
	h := &TokenReviewHandler{
		verifier:       v,
		config:         cfg,
		credStore:      store,
		statusProvider: sp,
		caches:         make(map[string]*cache.Cache[*authv1.TokenReview]),
		clients:        make(map[string]kubernetes.Interface),
	}

	if cfg != nil {
		for name := range cfg.Clusters {
			if cs := cfg.GetCacheSettings(name); cs != nil {
				h.caches[name] = cache.New[*authv1.TokenReview](
					time.Duration(cs.TTL)*time.Second, cs.MaxEntries,
				)
			}
		}
	}

	return h
}

func (h *TokenReviewHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Step 0: Authenticate the caller via their own SA token
	if h.config != nil && len(h.config.AuthorizedClients) > 0 {
		caller, authErr := h.authenticateCaller(r)
		if caller != "" {
			*r = *r.WithContext(mw.SetCallerIdentity(r.Context(), caller))
		}
		if authErr != nil {
			code := authErr.code
			if code == http.StatusUnauthorized && h.isDegraded() {
				code = http.StatusInternalServerError
			}
			*r = *r.WithContext(mw.SetErrorMessage(r.Context(), authErr.message))
			h.writeError(w, code, authErr.message)
			return
		}
	}

	// Parse TokenReview request
	var tr authv1.TokenReview
	if err := json.NewDecoder(r.Body).Decode(&tr); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if tr.Spec.Token == "" {
		h.writeError(w, http.StatusBadRequest, "token is required")
		return
	}

	if h.verifier == nil || h.config == nil {
		h.writeUnauthenticated(w, &tr, "server not configured")
		return
	}

	// Step 1: Detect cluster via JWKS (local, no token leakage)
	cluster, claims, err := h.detectCluster(r.Context(), tr.Spec.Token)
	if err != nil {
		*r = *r.WithContext(mw.SetErrorMessage(r.Context(), "token not valid for any configured cluster"))
		if h.isDegraded() {
			h.writeError(w, http.StatusInternalServerError, "token not valid for any configured cluster")
		} else {
			h.writeUnauthenticated(w, &tr, "token not valid for any configured cluster")
		}
		return
	}

	// Build client identity from claims for logging
	ns, sa := extractIdentity(claims)
	clientIdentity := fmt.Sprintf("%s/%s/%s", cluster, ns, sa)
	*r = *r.WithContext(mw.SetClientIdentity(r.Context(), clientIdentity))

	// Step 1.5: Check cache before forwarding
	cacheKey := cache.HashKey(cluster, tr.Spec.Token)
	if c, ok := h.caches[cluster]; ok {
		if cached, hit := c.Get(cacheKey); hit {
			slog.DebugContext(r.Context(), "cache hit", "cluster", cluster)
			result := cached.DeepCopy()
			json.NewEncoder(w).Encode(result)
			return
		}
	}

	// Step 2: Forward TokenReview to detected cluster
	result, err := h.forwardTokenReview(r.Context(), cluster, &tr)
	if err != nil {
		slog.ErrorContext(r.Context(), "tokenreview forwarding failed",
			"cluster", cluster, "error", err)
		h.writeUnauthenticated(w, &tr, fmt.Sprintf("failed to validate token: %v", err))
		return
	}

	// Add cluster name to extra field for client awareness
	if result.Status.Authenticated {
		if result.Status.User.Extra == nil {
			result.Status.User.Extra = make(map[string]authv1.ExtraValue)
		}
		result.Status.User.Extra[ExtraKeyClusterName] = authv1.ExtraValue{cluster}
	}

	// Cache authenticated results
	if result.Status.Authenticated {
		if c, ok := h.caches[cluster]; ok {
			c.Set(cacheKey, result.DeepCopy())
		}
	}

	// Return the response from the remote cluster
	json.NewEncoder(w).Encode(result)
}

type authError struct {
	code    int
	message string
}

func (e *authError) Error() string {
	return e.message
}

// authenticateCaller verifies the caller's own ServiceAccount token from the Authorization header.
// Returns the caller identity string on success, or an authError on failure.
func (h *TokenReviewHandler) authenticateCaller(r *http.Request) (string, *authError) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", &authError{http.StatusUnauthorized, "Authorization header required"}
	}

	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return "", &authError{http.StatusUnauthorized, "Authorization header must use Bearer scheme"}
	}

	callerToken := strings.TrimPrefix(authHeader, bearerPrefix)
	if callerToken == "" {
		return "", &authError{http.StatusUnauthorized, "bearer token is empty"}
	}

	if h.verifier == nil {
		return "", &authError{http.StatusInternalServerError, "server not configured for authentication"}
	}

	// Verify caller's token via JWKS to find the source cluster
	var callerCluster string
	var callerClaims *oidc.Claims
	for clusterName := range h.config.Clusters {
		claims, err := h.verifier.Verify(r.Context(), clusterName, callerToken)
		if err == nil {
			callerCluster = clusterName
			callerClaims = claims
			break
		}
	}

	if callerClaims == nil {
		return "", &authError{http.StatusUnauthorized, "caller token not valid for any configured cluster"}
	}

	// Extract namespace and service account from claims
	namespace, saName := extractIdentity(callerClaims)
	if namespace == "" || saName == "" {
		return "", &authError{http.StatusUnauthorized, "caller token missing identity claims"}
	}

	identity := fmt.Sprintf("%s/%s/%s", callerCluster, namespace, saName)

	// Check against authorized_clients whitelist
	if !h.config.IsAuthorizedClient(callerCluster, namespace, saName) {
		return identity, &authError{http.StatusForbidden, "caller is not authorized"}
	}

	return identity, nil
}

// extractIdentity extracts namespace and service account name from OIDC claims.
func extractIdentity(claims *oidc.Claims) (namespace, serviceAccount string) {
	if claims.Kubernetes == nil {
		return "", ""
	}

	if ns, ok := claims.Kubernetes["namespace"].(string); ok {
		namespace = ns
	}

	if sa, ok := claims.Kubernetes["serviceaccount"].(map[string]any); ok {
		if name, ok := sa["name"].(string); ok {
			serviceAccount = name
		}
	}

	return namespace, serviceAccount
}

// detectCluster tries to verify the token against all configured clusters using JWKS.
// This is done locally without sending the token anywhere.
// Returns the cluster name and claims from the successful verification.
func (h *TokenReviewHandler) detectCluster(ctx context.Context, token string) (string, *oidc.Claims, error) {
	for clusterName := range h.config.Clusters {
		claims, err := h.verifier.Verify(ctx, clusterName, token)
		if err == nil {
			return clusterName, claims, nil
		}
	}
	return "", nil, fmt.Errorf("token signature does not match any configured cluster")
}

// forwardTokenReview sends the TokenReview request to the detected cluster's API server.
func (h *TokenReviewHandler) forwardTokenReview(ctx context.Context, clusterName string, tr *authv1.TokenReview) (*authv1.TokenReview, error) {
	clusterCfg, ok := h.config.Clusters[clusterName]
	if !ok {
		return nil, fmt.Errorf("cluster not found: %s", clusterName)
	}

	// Get or create cached Kubernetes client
	client, err := h.getOrCreateClient(clusterName, clusterCfg)
	if err != nil {
		return nil, fmt.Errorf("getting kubernetes client: %w", err)
	}

	// Forward TokenReview request
	result, err := client.AuthenticationV1().TokenReviews().Create(ctx, tr, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("calling TokenReview API: %w", err)
	}

	// Ensure TypeMeta is set (k8s client doesn't populate this on responses)
	result.APIVersion = "authentication.k8s.io/v1"
	result.Kind = "TokenReview"

	return result, nil
}

// getOrCreateClient returns a cached Kubernetes client for the cluster, creating one if needed.
func (h *TokenReviewHandler) getOrCreateClient(clusterName string, clusterCfg config.ClusterConfig) (kubernetes.Interface, error) {
	h.clientsMu.RLock()
	if c, ok := h.clients[clusterName]; ok {
		h.clientsMu.RUnlock()
		return c, nil
	}
	h.clientsMu.RUnlock()

	h.clientsMu.Lock()
	defer h.clientsMu.Unlock()

	// Double-check after acquiring write lock
	if c, ok := h.clients[clusterName]; ok {
		return c, nil
	}

	restConfig, err := h.buildRESTConfig(clusterName, clusterCfg)
	if err != nil {
		return nil, fmt.Errorf("building REST config: %w", err)
	}

	client, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("creating kubernetes client: %w", err)
	}

	h.clients[clusterName] = client
	return client, nil
}

// buildRESTConfig creates a REST config for the target cluster
func (h *TokenReviewHandler) buildRESTConfig(clusterName string, clusterCfg config.ClusterConfig) (*rest.Config, error) {
	// For clusters with api_server, use remote credentials
	if clusterCfg.APIServer != "" {
		var bearerToken string
		var caCert []byte

		if h.credStore != nil {
			if creds, ok := h.credStore.Get(clusterName); ok {
				bearerToken = creds.Token
				caCert = creds.CACert
			}
		}

		rc := &rest.Config{
			Host:        clusterCfg.APIServer,
			BearerToken: bearerToken,
			TLSClientConfig: rest.TLSClientConfig{
				CAData: caCert,
			},
		}
		applyRateLimits(rc, clusterCfg)
		return rc, nil
	}

	// For local clusters, try in-cluster config first
	inClusterConfig, err := rest.InClusterConfig()
	if err == nil {
		applyRateLimits(inClusterConfig, clusterCfg)
		return inClusterConfig, nil
	}

	// Fallback: use issuer as host (for testing)
	rc := &rest.Config{
		Host: clusterCfg.Issuer,
	}
	applyRateLimits(rc, clusterCfg)
	return rc, nil
}

// applyRateLimits sets QPS and Burst on the REST config when configured.
func applyRateLimits(rc *rest.Config, clusterCfg config.ClusterConfig) {
	if clusterCfg.QPS > 0 {
		rc.QPS = clusterCfg.QPS
	}
	if clusterCfg.Burst > 0 {
		rc.Burst = clusterCfg.Burst
	}
}

func (h *TokenReviewHandler) writeUnauthenticated(w http.ResponseWriter, req *authv1.TokenReview, errMsg string) {
	resp := &authv1.TokenReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "authentication.k8s.io/v1",
			Kind:       "TokenReview",
		},
		Status: authv1.TokenReviewStatus{
			Authenticated: false,
			Error:         errMsg,
		},
	}

	json.NewEncoder(w).Encode(resp)
}

func (h *TokenReviewHandler) isDegraded() bool {
	if h.statusProvider == nil {
		return false
	}
	return len(h.statusProvider.DegradedClusters()) > 0
}

func (h *TokenReviewHandler) writeError(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	resp := &authv1.TokenReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "authentication.k8s.io/v1",
			Kind:       "TokenReview",
		},
		Status: authv1.TokenReviewStatus{
			Authenticated: false,
			Error:         msg,
		},
	}
	json.NewEncoder(w).Encode(resp)
}
