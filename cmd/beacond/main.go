// beacond is the Beacon API server daemon.
// It exposes a REST API for submitting scan jobs and retrieving results,
// backed by an in-memory worker pool and SQLite store.
//
// Usage:
//
//	beacond [--addr :8080] [--workers 4] [--db ~/.beacon/beacon.db]
//
// Configuration via environment variables (all BEACON_ prefixed):
//
//	BEACON_ADDR               listen address (default :8080)
//	BEACON_WORKERS            number of concurrent scans (default 2)
//	BEACON_API_KEY            bearer token for auth (default: open — not recommended)
//	BEACON_STORE_PATH         SQLite db path
//	BEACON_ANTHROPIC_API_KEY  enables AI enrichment
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/stormbane/beacon/internal/api"
	"github.com/stormbane/beacon/internal/config"
	sqlitestore "github.com/stormbane/beacon/internal/store/sqlite"
	"github.com/stormbane/beacon/internal/worker"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fatalf("config: %v", err)
	}

	addr := envOr("BEACON_ADDR", ":8080")
	workers := envInt("BEACON_WORKERS", 2)
	apiKey := envOr("BEACON_API_KEY", cfg.Server.APIKey)

	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "beacond: WARNING — no BEACON_API_KEY set, API is open to anyone")
	}

	st, err := sqlitestore.Open(cfg.Store.Path)
	if err != nil {
		fatalf("open store: %v", err)
	}
	defer st.Close()

	pool := worker.NewPool(workers, st, cfg)
	srv := api.New(st, pool, apiKey)

	server := &http.Server{
		Addr:         addr,
		Handler:      srv.Handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // SSE streams are long-lived
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown on SIGTERM / SIGINT.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		<-quit
		fmt.Fprintln(os.Stderr, "beacond: shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "beacond: shutdown error: %v\n", err)
		}
	}()

	fmt.Fprintf(os.Stderr, "beacond: listening on %s (workers=%d)\n", addr, workers)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fatalf("server: %v", err)
	}
	fmt.Fprintln(os.Stderr, "beacond: stopped")
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "beacond: "+format+"\n", args...)
	os.Exit(1)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
