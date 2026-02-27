package server

import (
	"log/slog"
	"net/http"

	"github.com/rophy/kube-federated-auth/internal/config"
	"github.com/rophy/kube-federated-auth/internal/credentials"
	"github.com/rophy/kube-federated-auth/internal/handler"
	mw "github.com/rophy/kube-federated-auth/internal/middleware"
	"github.com/rophy/kube-federated-auth/internal/oidc"
)

// Server holds the HTTP handler and verifier manager
type Server struct {
	Handler  http.Handler
	Verifier *oidc.VerifierManager
}

func New(cfg *config.Config, credStore *credentials.Store, version string) *Server {
	verifier := oidc.NewVerifierManager(cfg, credStore)
	logged := mw.RequestLogger(slog.Default())

	mux := http.NewServeMux()

	// Health endpoint without request logging to avoid spam from probes
	mux.Handle("GET /health", handler.NewHealthHandler(version))

	// Routes with slog-based request logging
	mux.Handle("GET /clusters", logged(handler.NewClustersHandler(cfg, credStore)))
	mux.Handle("POST /apis/authentication.k8s.io/v1/tokenreviews", logged(handler.NewTokenReviewHandler(verifier, cfg, credStore)))

	return &Server{
		Handler:  mw.Recoverer(mux),
		Verifier: verifier,
	}
}
