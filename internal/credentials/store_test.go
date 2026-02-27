package credentials

import (
	"os"
	"path/filepath"
	"testing"
)

func newTestStore() *Store {
	return &Store{
		credentials: make(map[string]*Credentials),
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

func TestLoadBootstrapFromFiles_LoadsWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	tokenPath, caPath := writeTestFiles(t, dir, "bootstrap-token", "bootstrap-ca")

	store := newTestStore()
	if err := store.LoadBootstrapFromFiles("cluster-b", tokenPath, caPath); err != nil {
		t.Fatal(err)
	}

	creds, ok := store.Get("cluster-b")
	if !ok {
		t.Fatal("expected credentials to be loaded")
	}
	if creds.Token != "bootstrap-token" {
		t.Errorf("expected token 'bootstrap-token', got '%s'", creds.Token)
	}
}

func TestLoadBootstrapFromFiles_PreservesTokenButLoadsCA(t *testing.T) {
	dir := t.TempDir()
	tokenPath, caPath := writeTestFiles(t, dir, "bootstrap-token", "bootstrap-ca")

	store := newTestStore()
	// Pre-populate with token only (as if loaded from Secret, which no longer stores CA)
	store.credentials["cluster-b"] = &Credentials{
		Token: "renewed-token",
	}

	if err := store.LoadBootstrapFromFiles("cluster-b", tokenPath, caPath); err != nil {
		t.Fatal(err)
	}

	creds, _ := store.Get("cluster-b")
	if creds.Token != "renewed-token" {
		t.Errorf("expected existing token 'renewed-token' to be preserved, got '%s'", creds.Token)
	}
	if string(creds.CACert) != "bootstrap-ca" {
		t.Errorf("expected CA cert 'bootstrap-ca' to be loaded from file, got '%s'", string(creds.CACert))
	}
}

func TestLoadFromFiles_AlwaysOverwrites(t *testing.T) {
	dir := t.TempDir()
	tokenPath, caPath := writeTestFiles(t, dir, "bootstrap-token", "bootstrap-ca")

	store := newTestStore()
	// Pre-populate with "renewed" credentials
	store.credentials["cluster-b"] = &Credentials{
		Token:  "renewed-token",
		CACert: []byte("renewed-ca"),
	}

	if err := store.LoadFromFiles("cluster-b", tokenPath, caPath); err != nil {
		t.Fatal(err)
	}

	creds, _ := store.Get("cluster-b")
	if creds.Token != "bootstrap-token" {
		t.Errorf("expected LoadFromFiles to overwrite with 'bootstrap-token', got '%s'", creds.Token)
	}
}
