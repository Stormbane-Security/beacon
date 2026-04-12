package portscan

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestRunMasscan_SkipsWhenBinEmpty(t *testing.T) {
	t.Parallel()
	results, err := RunMasscan(context.Background(), "10.0.0.0/24", "80,443", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Error("expected no results when masscanBin is empty")
	}
}

func TestRunMasscan_SkipsWhenBinNotFound(t *testing.T) {
	t.Parallel()
	results, err := RunMasscan(context.Background(), "10.0.0.0/24", "80,443", "masscan-nonexistent-binary-12345")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Error("expected no results when masscan binary not in PATH")
	}
}

func TestRunMasscan_SkipsSingleHost(t *testing.T) {
	t.Parallel()
	// masscan integration is only for CIDR notation, not single hosts.
	results, err := RunMasscan(context.Background(), "10.0.0.1", "80,443", "masscan")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Error("expected no results for single host (non-CIDR)")
	}
}

func TestParseMasscanOutput_ValidJSON(t *testing.T) {
	t.Parallel()
	jsonContent := `[
		{"ip": "10.0.0.1", "ports": [{"port": 80, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}]},
		{"ip": "10.0.0.2", "ports": [{"port": 443, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}]},
		{"ip": "10.0.0.1", "ports": [{"port": 8080, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}]}
	]`

	tmpFile := filepath.Join(t.TempDir(), "masscan-output.json")
	if err := os.WriteFile(tmpFile, []byte(jsonContent), 0o644); err != nil {
		t.Fatal(err)
	}

	results, err := parseMasscanOutput(tmpFile)
	if err != nil {
		t.Fatal(err)
	}

	sort.Strings(results)
	want := []string{"10.0.0.1:80", "10.0.0.1:8080", "10.0.0.2:443"}
	if len(results) != len(want) {
		t.Fatalf("got %d results, want %d: %v", len(results), len(want), results)
	}
	for i, r := range results {
		if r != want[i] {
			t.Errorf("result[%d] = %q, want %q", i, r, want[i])
		}
	}
}

func TestParseMasscanOutput_DeduplicatesPorts(t *testing.T) {
	t.Parallel()
	jsonContent := `[
		{"ip": "10.0.0.1", "ports": [{"port": 80, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}]},
		{"ip": "10.0.0.1", "ports": [{"port": 80, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}]}
	]`

	tmpFile := filepath.Join(t.TempDir(), "masscan-dedup.json")
	if err := os.WriteFile(tmpFile, []byte(jsonContent), 0o644); err != nil {
		t.Fatal(err)
	}

	results, err := parseMasscanOutput(tmpFile)
	if err != nil {
		t.Fatal(err)
	}

	if len(results) != 1 {
		t.Errorf("expected 1 deduplicated result, got %d: %v", len(results), results)
	}
}

func TestParseMasscanOutput_SkipsClosedPorts(t *testing.T) {
	t.Parallel()
	jsonContent := `[
		{"ip": "10.0.0.1", "ports": [{"port": 80, "proto": "tcp", "status": "closed", "reason": "rst", "ttl": 64}]}
	]`

	tmpFile := filepath.Join(t.TempDir(), "masscan-closed.json")
	if err := os.WriteFile(tmpFile, []byte(jsonContent), 0o644); err != nil {
		t.Fatal(err)
	}

	results, err := parseMasscanOutput(tmpFile)
	if err != nil {
		t.Fatal(err)
	}

	if len(results) != 0 {
		t.Errorf("expected 0 results for closed ports, got %d", len(results))
	}
}

func TestParseMasscanOutput_EmptyFile(t *testing.T) {
	t.Parallel()
	tmpFile := filepath.Join(t.TempDir(), "masscan-empty.json")
	if err := os.WriteFile(tmpFile, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	results, err := parseMasscanOutput(tmpFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty file, got %d", len(results))
	}
}

func TestParseMasscanOutput_MalformedJSON(t *testing.T) {
	t.Parallel()
	// masscan sometimes outputs JSON with trailing commas.
	jsonContent := `[
		{"ip": "10.0.0.1", "ports": [{"port": 80, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}]},
	]`

	tmpFile := filepath.Join(t.TempDir(), "masscan-malformed.json")
	if err := os.WriteFile(tmpFile, []byte(jsonContent), 0o644); err != nil {
		t.Fatal(err)
	}

	results, err := parseMasscanOutput(tmpFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 result from malformed JSON fixup, got %d: %v", len(results), results)
	}
}

func TestParseMasscanOutput_NonexistentFile(t *testing.T) {
	t.Parallel()
	results, err := parseMasscanOutput("/tmp/does-not-exist-masscan.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for nonexistent file, got %d", len(results))
	}
}
