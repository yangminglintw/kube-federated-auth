package credentials

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Credentials holds the token and CA certificate for a cluster
type Credentials struct {
	Token  string
	CACert []byte
}

// Store manages credentials for remote clusters
type Store struct {
	mu          sync.RWMutex
	credentials map[string]*Credentials
	managed     map[string]bool // clusters whose tokens should be persisted to Secret
	client      kubernetes.Interface
	namespace   string
	secretName  string
}

// NewStore creates a new credential store
// If running in-cluster, it will persist credentials to a Kubernetes Secret
func NewStore(namespace, secretName string) (*Store, error) {
	s := &Store{
		credentials: make(map[string]*Credentials),
		managed:     make(map[string]bool),
		namespace:   namespace,
		secretName:  secretName,
	}

	// Try to create in-cluster client
	config, err := rest.InClusterConfig()
	if err != nil {
		slog.Info("not running in cluster, credentials will not be persisted", "error", err)
		return s, nil
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		slog.Warn("failed to create kubernetes client, credentials will not be persisted", "error", err)
		return s, nil
	}

	s.client = client

	// Load existing credentials from Secret
	if err := s.loadFromSecret(context.Background()); err != nil {
		slog.Warn("failed to load credentials from secret", "error", err)
	}

	return s, nil
}

// Get returns credentials for a cluster
func (s *Store) Get(cluster string) (*Credentials, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	creds, ok := s.credentials[cluster]
	return creds, ok
}

// Set stores credentials for a cluster and persists to Secret
func (s *Store) Set(ctx context.Context, cluster string, creds *Credentials) error {
	s.mu.Lock()
	s.credentials[cluster] = creds
	s.managed[cluster] = true
	s.mu.Unlock()

	// Persist to Secret if we have a client
	if s.client != nil {
		if err := s.saveToSecret(ctx); err != nil {
			return fmt.Errorf("persisting credentials: %w", err)
		}
	}

	return nil
}

// loadFromSecret loads credentials from the Kubernetes Secret
func (s *Store) loadFromSecret(ctx context.Context) error {
	if s.client == nil {
		return nil
	}

	slog.Info("loading credentials from secret", "namespace", s.namespace, "secret", s.secretName)

	secret, err := s.client.CoreV1().Secrets(s.namespace).Get(ctx, s.secretName, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			slog.Info("credentials secret not found, starting fresh", "namespace", s.namespace, "secret", s.secretName)
			return nil
		}
		return fmt.Errorf("getting secret: %w", err)
	}

	slog.Info("found credentials secret", "namespace", s.namespace, "secret", s.secretName, "keys", len(secret.Data))

	s.mu.Lock()
	defer s.mu.Unlock()

	// Parse tokens from secret data (CA certs are loaded from files, not the secret)
	// Format: {name}-token
	for key, value := range secret.Data {
		if !strings.HasSuffix(key, "-token") {
			slog.Debug("skipping secret key", "key", key, "reason", "no -token suffix")
			continue
		}
		cluster := strings.TrimSuffix(key, "-token")
		token := string(value)
		if token == "" {
			slog.Warn("secret key has empty token", "key", key)
			continue
		}
		exp, err := getTokenExpiration(token)
		if err != nil {
			slog.Warn("secret key has invalid token", "key", key, "error", err)
		} else {
			slog.Info("loaded token from secret", "cluster", cluster, "expires", exp.Format(time.RFC3339))
		}
		s.credentials[cluster] = &Credentials{
			Token: token,
		}
		s.managed[cluster] = true
	}

	return nil
}

// saveToSecret persists all credentials to the Kubernetes Secret
func (s *Store) saveToSecret(ctx context.Context) error {
	if s.client == nil {
		return nil
	}

	s.mu.RLock()
	data := make(map[string][]byte)
	for cluster, creds := range s.credentials {
		if !s.managed[cluster] {
			continue
		}
		data[fmt.Sprintf("%s-token", cluster)] = []byte(creds.Token)
	}
	s.mu.RUnlock()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      s.secretName,
			Namespace: s.namespace,
		},
		Data: data,
	}

	// Try to update first, create if not exists
	_, err := s.client.CoreV1().Secrets(s.namespace).Update(ctx, secret, metav1.UpdateOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			_, err = s.client.CoreV1().Secrets(s.namespace).Create(ctx, secret, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("creating secret: %w", err)
			}
			slog.Info("created credentials secret", "namespace", s.namespace, "secret", s.secretName)
			return nil
		}
		return fmt.Errorf("updating secret: %w", err)
	}

	slog.Info("updated credentials secret", "namespace", s.namespace, "secret", s.secretName)
	return nil
}

// LoadCACertFromFile loads a CA certificate from file into the credential store.
// CA certs are long-lived and always read from mounted files, never persisted in the Secret.
func (s *Store) LoadCACertFromFile(cluster, caPath string) error {
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return fmt.Errorf("reading CA file: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.credentials[cluster]; ok {
		existing.CACert = ca
	} else {
		s.credentials[cluster] = &Credentials{CACert: ca}
	}

	slog.Info("loaded CA cert from file", "cluster", cluster)
	return nil
}

// LoadBootstrapToken loads a bootstrap token from file, only if no token is already present
// (e.g., from a persisted Secret). Tokens are short-lived and will be renewed and persisted.
func (s *Store) LoadBootstrapToken(cluster, tokenPath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.credentials[cluster]; ok && existing.Token != "" {
		slog.Info("token already present, skipping bootstrap", "cluster", cluster)
		return nil
	}

	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return fmt.Errorf("reading token file: %w", err)
	}

	if existing, ok := s.credentials[cluster]; ok {
		existing.Token = string(token)
	} else {
		s.credentials[cluster] = &Credentials{Token: string(token)}
	}

	slog.Info("loaded bootstrap token from file", "cluster", cluster)
	return nil
}

// LoadFromFiles loads both token and CA cert from files, overwriting any existing credentials.
// Used by the renewer for bootstrap fallback when the current token fails.
func (s *Store) LoadFromFiles(cluster, tokenPath, caPath string) error {
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return fmt.Errorf("reading token file: %w", err)
	}

	ca, err := os.ReadFile(caPath)
	if err != nil {
		return fmt.Errorf("reading CA file: %w", err)
	}

	s.mu.Lock()
	s.credentials[cluster] = &Credentials{
		Token:  string(token),
		CACert: ca,
	}
	s.mu.Unlock()

	slog.Info("loaded credentials from files", "cluster", cluster)
	return nil
}
