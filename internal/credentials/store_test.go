package credentials

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rophy/kube-federated-auth/internal/config"
)

func newTestStore() *Store {
	return &Store{
		credentials: make(map[string]*Credentials),
		config:      &config.Config{Clusters: make(map[string]config.ClusterConfig)},
	}
}

func writeTestFiles(t *testing.T, dir, token, ca string) (tokenPath, caPath string) {
	t.Helper()
	tokenPath = filepath.Join(dir, "token")
	caPath = filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(tokenPath, []byte(token), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, []byte(ca), 0644); err != nil {
		t.Fatal(err)
	}
	return
}

func TestSetCACert_LoadsWhenEmpty(t *testing.T) {
	store := newTestStore()
	store.setCACert("cluster-b", []byte("test-ca"))

	creds, ok := store.Get("cluster-b")
	if !ok {
		t.Fatal("expected credentials to be created")
	}
	if string(creds.CACert) != "test-ca" {
		t.Errorf("expected CA cert 'test-ca', got '%s'", string(creds.CACert))
	}
	if creds.Token != "" {
		t.Errorf("expected empty token, got '%s'", creds.Token)
	}
}

func TestSetCACert_SetsCAOnExisting(t *testing.T) {
	store := newTestStore()
	store.credentials["cluster-b"] = &Credentials{Token: "existing-token"}

	store.setCACert("cluster-b", []byte("test-ca"))

	creds, _ := store.Get("cluster-b")
	if creds.Token != "existing-token" {
		t.Errorf("expected token preserved, got '%s'", creds.Token)
	}
	if string(creds.CACert) != "test-ca" {
		t.Errorf("expected CA cert 'test-ca', got '%s'", string(creds.CACert))
	}
}

func TestSetToken_LoadsWhenEmpty(t *testing.T) {
	store := newTestStore()
	store.SetToken("cluster-b", "test-token")

	creds, ok := store.Get("cluster-b")
	if !ok {
		t.Fatal("expected credentials to be created")
	}
	if creds.Token != "test-token" {
		t.Errorf("expected token 'test-token', got '%s'", creds.Token)
	}
}

func TestSetToken_OverwritesExisting(t *testing.T) {
	store := newTestStore()
	store.credentials["cluster-b"] = &Credentials{
		Token:  "old-token",
		CACert: []byte("existing-ca"),
	}

	store.SetToken("cluster-b", "new-token")

	creds, _ := store.Get("cluster-b")
	if creds.Token != "new-token" {
		t.Errorf("expected token 'new-token', got '%s'", creds.Token)
	}
	if string(creds.CACert) != "existing-ca" {
		t.Errorf("expected CA cert preserved, got '%s'", string(creds.CACert))
	}
}

func TestNewStore_LoadsFromFiles(t *testing.T) {
	dir := t.TempDir()
	tokenPath, caPath := writeTestFiles(t, dir, "bootstrap-token", "test-ca")

	cfg := &config.Config{
		Clusters: map[string]config.ClusterConfig{
			"cluster-b": {
				Issuer:    "https://example.com",
				TokenPath: tokenPath,
				CACert:    caPath,
			},
		},
	}

	store, err := NewStore(cfg, "test-secret")
	if err != nil {
		t.Fatal(err)
	}

	creds, ok := store.Get("cluster-b")
	if !ok {
		t.Fatal("expected credentials to be created")
	}
	if creds.Token != "bootstrap-token" {
		t.Errorf("expected token 'bootstrap-token', got '%s'", creds.Token)
	}
	if string(creds.CACert) != "test-ca" {
		t.Errorf("expected CA cert 'test-ca', got '%s'", string(creds.CACert))
	}
	if creds.source != tokenMounted {
		t.Errorf("expected source tokenMounted, got %d", creds.source)
	}
}

func TestNewStore_SkipsMissingFiles(t *testing.T) {
	cfg := &config.Config{
		Clusters: map[string]config.ClusterConfig{
			"cluster-b": {
				Issuer:    "https://example.com",
				TokenPath: "/nonexistent/token",
				CACert:    "/nonexistent/ca.crt",
			},
		},
	}

	store, err := NewStore(cfg, "test-secret")
	if err != nil {
		t.Fatal(err)
	}

	_, ok := store.Get("cluster-b")
	if ok {
		t.Error("expected no credentials for missing files")
	}
}

func TestRenewMountedToken(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	os.WriteFile(tokenPath, []byte("original-token"), 0644)

	store := newTestStore()
	store.credentials["cluster-a"] = &Credentials{
		Token:  "original-token",
		source: tokenMounted,
	}

	cfg := config.ClusterConfig{TokenPath: tokenPath}

	// Write new token to file (simulating kubelet rotation)
	os.WriteFile(tokenPath, []byte("rotated-token"), 0644)

	if err := store.renewMountedToken("cluster-a", cfg); err != nil {
		t.Fatal(err)
	}

	creds, _ := store.Get("cluster-a")
	if creds.Token != "rotated-token" {
		t.Errorf("expected 'rotated-token', got '%s'", creds.Token)
	}
	if creds.source != tokenMounted {
		t.Errorf("expected source tokenMounted after renewal")
	}
}
