package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/rophy/kube-federated-auth/internal/config"
	"github.com/rophy/kube-federated-auth/internal/credentials"
	"github.com/rophy/kube-federated-auth/internal/server"
)

// Version is set at build time via -ldflags "-X main.Version=..."
var Version = "dev"

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	configPath := flag.String("config", getEnv("CONFIG_PATH", "config/clusters.yaml"), "path to cluster config file")
	port := flag.String("port", getEnv("PORT", "8080"), "server port")
	secretName := flag.String("secret-name", getEnv("SECRET_NAME", "kube-federated-auth"), "name of credential secret")
	flag.Parse()

	namespace := detectNamespace()

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	slog.Info("config loaded", "clusters", cfg.ClusterNames(), "count", len(cfg.Clusters))

	// Only create credential store if there are remote clusters
	var credStore *credentials.Store
	remoteClusters := cfg.GetRemoteClusters()
	if len(remoteClusters) > 0 {
		var err error
		credStore, err = credentials.NewStore(namespace, *secretName)
		if err != nil {
			slog.Error("failed to create credential store", "error", err)
			os.Exit(1)
		}

		// Load CA certs and bootstrap tokens separately — they have different lifecycles:
		// - CA certs: long-lived, always from file, never persisted in Secret
		// - Tokens: short-lived, from Secret if available, otherwise from bootstrap file
		for clusterName, clusterCfg := range cfg.Clusters {
			if clusterCfg.CACert != "" {
				if err := credStore.LoadCACertFromFile(clusterName, clusterCfg.CACert); err != nil {
					slog.Warn("could not load CA cert", "cluster", clusterName, "error", err)
				}
			}
			if clusterCfg.TokenPath != "" {
				if err := credStore.LoadBootstrapToken(clusterName, clusterCfg.TokenPath); err != nil {
					slog.Warn("could not load bootstrap token", "cluster", clusterName, "error", err)
				}
			}
		}
	}

	slog.Info("starting server", "version", Version, "addr", ":"+*port)
	srv := server.New(cfg, credStore, Version)

	// Start credential renewal for remote clusters
	if len(remoteClusters) > 0 {
		slog.Info("starting credential renewal", "remote_clusters", remoteClusters)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		renewer := credentials.NewRenewer(cfg, credStore, srv.Verifier)
		renewer.Start(ctx)

		// Handle shutdown gracefully
		go func() {
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
			<-sigCh
			slog.Info("shutting down")
			cancel()
		}()
	}

	addr := ":" + *port
	if err := http.ListenAndServe(addr, srv.Handler); err != nil {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}

func detectNamespace() string {
	if ns, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		return string(ns)
	}
	return "kube-federated-auth"
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
