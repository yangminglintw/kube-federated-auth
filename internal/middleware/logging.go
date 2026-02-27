package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
)

type contextKey int

const (
	callerIdentityKey contextKey = iota
	clientIdentityKey
	errorMessageKey
)

// SetCallerIdentity stores the caller identity in the request context.
func SetCallerIdentity(ctx context.Context, identity string) context.Context {
	return context.WithValue(ctx, callerIdentityKey, identity)
}

// GetCallerIdentity retrieves the caller identity from context.
func GetCallerIdentity(ctx context.Context) string {
	if v, ok := ctx.Value(callerIdentityKey).(string); ok {
		return v
	}
	return ""
}

// SetClientIdentity stores the client (payload token) identity in the request context.
func SetClientIdentity(ctx context.Context, identity string) context.Context {
	return context.WithValue(ctx, clientIdentityKey, identity)
}

// GetClientIdentity retrieves the client identity from context.
func GetClientIdentity(ctx context.Context) string {
	if v, ok := ctx.Value(clientIdentityKey).(string); ok {
		return v
	}
	return ""
}

// SetErrorMessage stores an error message in the request context for logging.
func SetErrorMessage(ctx context.Context, msg string) context.Context {
	return context.WithValue(ctx, errorMessageKey, msg)
}

// GetErrorMessage retrieves the error message from context.
func GetErrorMessage(ctx context.Context) string {
	if v, ok := ctx.Value(errorMessageKey).(string); ok {
		return v
	}
	return ""
}

// RequestLogger returns an slog-based request logging middleware.
// It logs one line per request with method, path, status, duration,
// and optionally caller identity and cluster name from context.
func RequestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)

			next.ServeHTTP(ww, r)

			attrs := []slog.Attr{
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", ww.Status()),
				slog.String("duration", time.Since(start).Round(time.Microsecond).String()),
			}

			if caller := GetCallerIdentity(r.Context()); caller != "" {
				attrs = append(attrs, slog.String("caller", caller))
			}
			if client := GetClientIdentity(r.Context()); client != "" {
				attrs = append(attrs, slog.String("client", client))
			}
			errMsg := GetErrorMessage(r.Context())
			if errMsg != "" {
				attrs = append(attrs, slog.String("error", errMsg))
			}

			level := slog.LevelInfo
			if ww.Status() >= 500 {
				level = slog.LevelError
			} else if ww.Status() >= 400 || errMsg != "" {
				level = slog.LevelWarn
			}

			logger.LogAttrs(r.Context(), level, "http request", attrs...)
		})
	}
}
