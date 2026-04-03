package scanlog

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
)

func TestNew_FileOutput(t *testing.T) {
	tmp, err := os.CreateTemp(t.TempDir(), "beacon-log-*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	l := New(tmp.Name(), slog.LevelDebug)
	l.ScanStart("example.com", "surface", []string{"example.com"})
	l.Finding(finding.Finding{
		CheckID:  "web.cors_misconfigured",
		Scanner:  "cors",
		Asset:    "example.com",
		Severity: finding.SeverityHigh,
		Title:    "CORS wildcard origin",
		Module:   "surface",
		Evidence: map[string]any{
			"origin": "*",
		},
		DiscoveredAt: time.Now(),
	})
	l.ScannerStart("cors", "example.com")
	l.ScannerComplete("cors", "example.com", 1, 200*time.Millisecond)
	l.ScanComplete("example.com", 1, 5*time.Second)
	l.Close()

	data, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 5 {
		t.Fatalf("expected 5 log lines, got %d", len(lines))
	}

	// Verify each line is valid JSON
	for i, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Errorf("line %d is not valid JSON: %v", i, err)
		}
	}

	// Verify scan.start event
	var start map[string]any
	json.Unmarshal([]byte(lines[0]), &start)
	if start["msg"] != "scan.start" {
		t.Errorf("expected scan.start, got %v", start["msg"])
	}
	if start["domain"] != "example.com" {
		t.Errorf("expected domain=example.com, got %v", start["domain"])
	}

	// Verify finding event
	var f map[string]any
	json.Unmarshal([]byte(lines[1]), &f)
	if f["msg"] != "finding.discovered" {
		t.Errorf("expected finding.discovered, got %v", f["msg"])
	}
	if f["check_id"] != "web.cors_misconfigured" {
		t.Errorf("expected check_id=web.cors_misconfigured, got %v", f["check_id"])
	}
	if f["evidence.origin"] != "*" {
		t.Errorf("expected evidence.origin=*, got %v", f["evidence.origin"])
	}
}

func TestNew_Stderr(t *testing.T) {
	// Empty path => stderr (no crash)
	l := New("", slog.LevelInfo)
	l.ScanStart("test.com", "surface", nil)
	l.Close()
}

func TestFromContext_NilReturnsNop(t *testing.T) {
	ctx := context.Background()
	l := FromContext(ctx)
	// Should not panic
	l.ScanStart("test.com", "surface", nil)
	l.Finding(finding.Finding{CheckID: "test"})
}

func TestWithLogger_RoundTrip(t *testing.T) {
	l := New("", slog.LevelDebug)
	ctx := WithLogger(context.Background(), l)
	got := FromContext(ctx)
	if got != l {
		t.Error("expected same logger from context")
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input string
		want  slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"error", slog.LevelError},
		{"unknown", slog.LevelInfo},
		{"", slog.LevelInfo},
	}
	for _, tt := range tests {
		if got := ParseLevel(tt.input); got != tt.want {
			t.Errorf("ParseLevel(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestExploitChainLogging(t *testing.T) {
	tmp, err := os.CreateTemp(t.TempDir(), "beacon-exploit-*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	l := New(tmp.Name(), slog.LevelDebug)
	l.ExploitChainStart("cmdinj", "target.com", "/api/exec?cmd=")
	l.ExploitChainStep("cmdinj", "target.com", "host_discovery", "10.0.0.1:6379", true)
	l.ExploitChainStep("cmdinj", "target.com", "redis_probe", "10.0.0.1:6379", true)
	l.ExploitChainComplete("cmdinj", "target.com", 3)
	l.Close()

	data, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected 4 log lines, got %d", len(lines))
	}

	var chainStart map[string]any
	json.Unmarshal([]byte(lines[0]), &chainStart)
	if chainStart["msg"] != "exploit.chain_start" {
		t.Errorf("expected exploit.chain_start, got %v", chainStart["msg"])
	}
}
