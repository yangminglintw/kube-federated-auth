package credentials

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

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
	client      kubernetes.Interface
	namespace   string
	secretName  string
}

// NewStore creates a new credential store
// If running in-cluster, it will persist credentials to a Kubernetes Secret
func NewStore(namespace, secretName string) (*Store, error) {
	s := &Store{
		credentials: make(map[string]*Credentials),
		namespace:   namespace,
		secretName:  secretName,
	}

	// Try to create in-cluster client
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Printf("Not running in cluster, credentials will not be persisted: %v", err)
		return s, nil
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Printf("Failed to create Kubernetes client, credentials will not be persisted: %v", err)
		return s, nil
	}

	s.client = client

	// Load existing credentials from Secret
	if err := s.loadFromSecret(context.Background()); err != nil {
		log.Printf("Failed to load credentials from secret: %v", err)
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

	log.Printf("Loading credentials from secret %s/%s", s.namespace, s.secretName)

	secret, err := s.client.CoreV1().Secrets(s.namespace).Get(ctx, s.secretName, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			log.Printf("Credentials secret %s/%s not found, starting fresh", s.namespace, s.secretName)
			return nil
		}
		return fmt.Errorf("getting secret: %w", err)
	}

	log.Printf("Found secret %s/%s with %d data keys", s.namespace, s.secretName, len(secret.Data))

	s.mu.Lock()
	defer s.mu.Unlock()

	// Parse tokens from secret data (CA certs are loaded from files, not the secret)
	// Format: {name}-token
	for key, value := range secret.Data {
		if !strings.HasSuffix(key, "-token") {
			log.Printf("Skipping secret key %q (no -token suffix)", key)
			continue
		}
		cluster := strings.TrimSuffix(key, "-token")
		token := string(value)
		if token == "" {
			log.Printf("WARNING: secret key %q has empty token value", key)
			continue
		}
		exp, err := getTokenExpiration(token)
		if err != nil {
			log.Printf("WARNING: secret key %q has invalid token: %v", key, err)
		} else {
			log.Printf("Loaded token for cluster %s from secret (expires: %s)", cluster, exp.Format("2006-01-02T15:04:05Z"))
		}
		s.credentials[cluster] = &Credentials{
			Token: token,
		}
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
			log.Printf("Created credentials secret %s/%s", s.namespace, s.secretName)
			return nil
		}
		return fmt.Errorf("updating secret: %w", err)
	}

	log.Printf("Updated credentials secret %s/%s", s.namespace, s.secretName)
	return nil
}

// LoadBootstrapFromFiles loads bootstrap credentials from files.
// CA cert is always loaded from file (not persisted in the Secret).
// Token is only loaded from file if not already present (e.g., from a persisted Secret).
func (s *Store) LoadBootstrapFromFiles(cluster, tokenPath, caPath string) error {
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return fmt.Errorf("reading CA file: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.credentials[cluster]; ok {
		existing.CACert = ca
		log.Printf("Loaded CA cert for cluster %s from file (token already from secret)", cluster)
		return nil
	}

	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return fmt.Errorf("reading token file: %w", err)
	}

	s.credentials[cluster] = &Credentials{
		Token:  string(token),
		CACert: ca,
	}
	log.Printf("Loaded bootstrap credentials for cluster %s from files", cluster)
	return nil
}

// LoadFromFiles loads bootstrap credentials from files (for initial setup)
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

	log.Printf("Loaded bootstrap credentials for cluster %s from files", cluster)
	return nil
}