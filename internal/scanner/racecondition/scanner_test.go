package racecondition

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/module"
)

func TestRaceConditionDetected(t *testing.T) {
	// Server that always returns 200 on POST /api/redeem — no deduplication.
	// This simulates a vulnerable endpoint that doesn't prevent double-redemption.
	var count atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/redeem" && r.Method == http.MethodPost {
			count.Add(1)
			w.WriteHeader(200)
			w.Write([]byte(`{"success": true}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	s := New()
	findings, err := s.Run(context.Background(), srv.Listener.Addr().String(), module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected race condition finding, got none")
	}
	if findings[0].CheckID != "web.race_condition" {
		t.Errorf("expected web.race_condition, got %s", findings[0].CheckID)
	}
	t.Logf("race condition endpoint received %d requests", count.Load())
}

func TestNoRaceOnIdempotentServer(t *testing.T) {
	// Server that returns 404 on all race target paths.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()

	s := New()
	findings, err := s.Run(context.Background(), srv.Listener.Addr().String(), module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings on 404 server, got %d", len(findings))
	}
}

func TestRaceConcurrentRelease(t *testing.T) {
	// Verify the channel barrier releases all goroutines simultaneously (not
	// sequentially as a sync.Mutex would). A vulnerable server that tracks
	// arrival order should see overlapping requests.
	var maxConcurrent atomic.Int64
	var current atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/redeem" && r.Method == http.MethodPost {
			n := current.Add(1)
			// Track peak concurrency.
			for {
				old := maxConcurrent.Load()
				if n <= old || maxConcurrent.CompareAndSwap(old, n) {
					break
				}
			}
			// Hold the request open briefly to overlap with others.
			select {
			case <-r.Context().Done():
			case <-func() <-chan struct{} {
				ch := make(chan struct{})
				go func() { defer close(ch); <-time.After(20 * time.Millisecond) }()
				return ch
			}():
			}
			current.Add(-1)
			w.WriteHeader(200)
			w.Write([]byte(`{"success": true}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	s := New()
	_, err := s.Run(context.Background(), srv.Listener.Addr().String(), module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	peak := maxConcurrent.Load()
	if peak <= 1 {
		t.Errorf("expected concurrent requests > 1 (barrier should release simultaneously), got peak %d", peak)
	}
	t.Logf("peak concurrent requests: %d", peak)
}

func TestSurfaceModeSkips(t *testing.T) {
	s := New()
	findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings in surface mode, got %d", len(findings))
	}
}
