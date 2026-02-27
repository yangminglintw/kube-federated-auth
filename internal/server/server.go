package server

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
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
	r := chi.NewRouter()

	r.Use(chimw.Recoverer)
	r.Use(chimw.RequestID)

	verifier := oidc.NewVerifierManager(cfg, credStore)

	// Health endpoint without request logging to avoid spam from probes
	r.Get("/health", handler.NewHealthHandler(version).ServeHTTP)

	// All other routes with slog-based request logging
	r.Group(func(r chi.Router) {
		r.Use(mw.RequestLogger(slog.Default()))
		r.Get("/clusters", handler.NewClustersHandler(cfg, credStore).ServeHTTP)
		r.Post("/apis/authentication.k8s.io/v1/tokenreviews", handler.NewTokenReviewHandler(verifier, cfg, credStore).ServeHTTP)
	})

	return &Server{
		Handler:  r,
		Verifier: verifier,
	}
}
