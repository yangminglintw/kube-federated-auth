package credentials

import (
	"os"
	"path/filepath"
	"testing"
)

func newTestStore() *Store {
	return &Store{
		credentials: make(map[string]*Credentials),
		managed:     make(map[string]bool),
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

func TestLoadCACertFromFile_LoadsWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	_, caPath := writeTestFiles(t, dir, "", "test-ca")

	store := newTestStore()
	if err := store.LoadCACertFromFile("cluster-b", caPath); err != nil {
		t.Fatal(err)
	}

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

func TestLoadCACertFromFile_SetsCAOnExisting(t *testing.T) {
	dir := t.TempDir()
	_, caPath := writeTestFiles(t, dir, "", "test-ca")

	store := newTestStore()
	store.credentials["cluster-b"] = &Credentials{Token: "existing-token"}

	if err := store.LoadCACertFromFile("cluster-b", caPath); err != nil {
		t.Fatal(err)
	}

	creds, _ := store.Get("cluster-b")
	if creds.Token != "existing-token" {
		t.Errorf("expected token preserved, got '%s'", creds.Token)
	}
	if string(creds.CACert) != "test-ca" {
		t.Errorf("expected CA cert 'test-ca', got '%s'", string(creds.CACert))
	}
}

func TestLoadBootstrapToken_LoadsWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	tokenPath, _ := writeTestFiles(t, dir, "bootstrap-token", "")

	store := newTestStore()
	if err := store.LoadBootstrapToken("cluster-b", tokenPath); err != nil {
		t.Fatal(err)
	}

	creds, ok := store.Get("cluster-b")
	if !ok {
		t.Fatal("expected credentials to be created")
	}
	if creds.Token != "bootstrap-token" {
		t.Errorf("expected token 'bootstrap-token', got '%s'", creds.Token)
	}
}

func TestLoadBootstrapToken_SkipsWhenTokenExists(t *testing.T) {
	dir := t.TempDir()
	tokenPath, _ := writeTestFiles(t, dir, "bootstrap-token", "")

	store := newTestStore()
	store.credentials["cluster-b"] = &Credentials{Token: "renewed-token"}

	if err := store.LoadBootstrapToken("cluster-b", tokenPath); err != nil {
		t.Fatal(err)
	}

	creds, _ := store.Get("cluster-b")
	if creds.Token != "renewed-token" {
		t.Errorf("expected existing token preserved, got '%s'", creds.Token)
	}
}

func TestLoadFromFiles_AlwaysOverwrites(t *testing.T) {
	dir := t.TempDir()
	tokenPath, caPath := writeTestFiles(t, dir, "bootstrap-token", "bootstrap-ca")

	store := newTestStore()
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
