package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/rophy/kube-federated-auth/internal/config"
)

func TestExtractKID(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		wantKID string
	}{
		{
			name:    "valid JWT with kid",
			token:   makeJWTHeader(map[string]any{"alg": "RS256", "kid": "key-123"}) + ".payload.signature",
			wantKID: "key-123",
		},
		{
			name:    "valid JWT without kid",
			token:   makeJWTHeader(map[string]any{"alg": "RS256"}) + ".payload.signature",
			wantKID: "",
		},
		{
			name:    "malformed token - no dots",
			token:   "notavalidtoken",
			wantKID: "",
		},
		{
			name:    "malformed token - invalid base64",
			token:   "!!!invalid!!!.payload.signature",
			wantKID: "",
		},
		{
			name:    "malformed token - invalid JSON",
			token:   base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".payload.signature",
			wantKID: "",
		},
		{
			name:    "empty string",
			token:   "",
			wantKID: "",
		},
		{
			name:    "kid is empty string",
			token:   makeJWTHeader(map[string]any{"alg": "RS256", "kid": ""}) + ".payload.signature",
			wantKID: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractKID(tt.token)
			if got != tt.wantKID {
				t.Errorf("extractKID() = %q, want %q", got, tt.wantKID)
			}
		})
	}
}

func TestFetchKIDs(t *testing.T) {
	jwks := `{"keys":[{"kid":"k1","kty":"RSA"},{"kid":"k2","kty":"RSA"},{"kty":"RSA"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, jwks)
	}))
	defer srv.Close()

	kids, err := fetchKIDs(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("fetchKIDs() error: %v", err)
	}
	if len(kids) != 2 {
		t.Fatalf("fetchKIDs() returned %d kids, want 2", len(kids))
	}
	if kids[0] != "k1" || kids[1] != "k2" {
		t.Errorf("fetchKIDs() = %v, want [k1, k2]", kids)
	}
}

func TestFetchKIDs_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := fetchKIDs(context.Background(), srv.Client(), srv.URL)
	if err == nil {
		t.Fatal("fetchKIDs() should return error on non-200 status")
	}
}

func TestVerifyKIDShortCircuit(t *testing.T) {
	cfg := &config.Config{
		Clusters: map[string]config.ClusterConfig{
			"cluster-a": {Issuer: "https://a.example.com"},
			"cluster-b": {Issuer: "https://b.example.com"},
		},
	}
	mgr := NewVerifierManager(cfg, nil)
	mgr.kidToCluster["key-cluster-a"] = "cluster-a"
	mgr.kidToCluster["key-cluster-b"] = "cluster-b"

	// Build a token with kid belonging to cluster-a
	token := makeJWTHeader(map[string]any{"alg": "RS256", "kid": "key-cluster-a"}) + ".payload.signature"

	// Verify against cluster-b should be short-circuited (no go-oidc call)
	_, err := mgr.Verify(context.Background(), "cluster-b", token)
	if err == nil {
		t.Fatal("Verify() should return error for wrong-cluster kid")
	}
	wantMsg := `kid "key-cluster-a" belongs to cluster cluster-a, not cluster-b`
	if err.Error() != wantMsg {
		t.Errorf("Verify() error = %q, want %q", err.Error(), wantMsg)
	}
}

func TestVerifyUnknownKIDFallsThrough(t *testing.T) {
	cfg := &config.Config{
		Clusters: map[string]config.ClusterConfig{
			"cluster-b": {Issuer: "https://b.example.com"},
		},
	}
	mgr := NewVerifierManager(cfg, nil)
	mgr.kidToCluster["key-cluster-a"] = "cluster-a"

	token := makeJWTHeader(map[string]any{"alg": "RS256", "kid": "unknown-key"}) + ".payload.signature"

	_, err := mgr.Verify(context.Background(), "cluster-b", token)
	if err == nil {
		t.Fatal("Verify() should fail (no real verifier)")
	}
	// Should NOT be the kid short-circuit error
	if strings.Contains(err.Error(), "belongs to cluster") {
		t.Errorf("unknown kid should fall through, got short-circuit error: %v", err)
	}
}

func TestInvalidateVerifierClearsKIDs(t *testing.T) {
	mgr := &VerifierManager{
		kidToCluster: map[string]string{
			"k1": "cluster-a",
			"k2": "cluster-a",
			"k3": "cluster-b",
		},
		verifiers: make(map[string]*gooidc.IDTokenVerifier),
	}

	mgr.InvalidateVerifier("cluster-a")

	if len(mgr.kidToCluster) != 1 {
		t.Fatalf("kidToCluster has %d entries, want 1", len(mgr.kidToCluster))
	}
	if mgr.kidToCluster["k3"] != "cluster-b" {
		t.Error("cluster-b kid should remain after invalidating cluster-a")
	}
}

func TestRewriteJWKSURL(t *testing.T) {
	tests := []struct {
		name      string
		jwksURL   string
		apiServer string
		want      string
	}{
		{
			name:      "standard k8s URL rewritten",
			jwksURL:   "https://kubernetes.default.svc.cluster.local/openid/v1/jwks",
			apiServer: "https://10.0.0.1:6443",
			want:      "https://10.0.0.1:6443/openid/v1/jwks",
		},
		{
			name:      "URL without /openid/v1/jwks returned as-is",
			jwksURL:   "https://example.com/.well-known/jwks.json",
			apiServer: "https://10.0.0.1:6443",
			want:      "https://example.com/.well-known/jwks.json",
		},
		{
			name:      "apiServer trailing slash trimmed",
			jwksURL:   "https://kubernetes.default.svc/openid/v1/jwks",
			apiServer: "https://10.0.0.1:6443/",
			want:      "https://10.0.0.1:6443/openid/v1/jwks",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rewriteJWKSURL(tt.jwksURL, tt.apiServer)
			if got != tt.want {
				t.Errorf("rewriteJWKSURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

// makeJWTHeader encodes a JSON object as a base64url JWT header segment.
func makeJWTHeader(header map[string]any) string {
	b, _ := json.Marshal(header)
	return base64.RawURLEncoding.EncodeToString(b)
}
