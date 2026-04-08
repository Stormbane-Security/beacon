package paramdiscovery

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRunArjun_SkipsWhenBinEmpty(t *testing.T) {
	t.Parallel()
	results, err := runArjun(context.Background(), "https://example.com", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Error("expected no results when arjunBin is empty")
	}
}

func TestRunArjun_SkipsWhenBinNotFound(t *testing.T) {
	t.Parallel()
	results, err := runArjun(context.Background(), "https://example.com", "arjun-nonexistent-binary-12345", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Error("expected no results when arjun binary not in PATH")
	}
}

func TestParseArjunOutput_ValidJSON(t *testing.T) {
	t.Parallel()
	jsonContent := `{
		"https://example.com": ["id", "name", "page"],
		"https://example.com/api": ["token", "id"]
	}`

	tmpFile := filepath.Join(t.TempDir(), "arjun-output.json")
	if err := os.WriteFile(tmpFile, []byte(jsonContent), 0o644); err != nil {
		t.Fatal(err)
	}

	params, err := parseArjunOutput(tmpFile)
	if err != nil {
		t.Fatal(err)
	}

	// Should be deduplicated and sorted.
	want := []string{"id", "name", "page", "token"}
	if !reflect.DeepEqual(params, want) {
		t.Errorf("parseArjunOutput = %v, want %v", params, want)
	}
}

func TestParseArjunOutput_EmptyResult(t *testing.T) {
	t.Parallel()
	jsonContent := `{}`

	tmpFile := filepath.Join(t.TempDir(), "arjun-empty.json")
	if err := os.WriteFile(tmpFile, []byte(jsonContent), 0o644); err != nil {
		t.Fatal(err)
	}

	params, err := parseArjunOutput(tmpFile)
	if err != nil {
		t.Fatal(err)
	}

	if len(params) != 0 {
		t.Errorf("expected 0 params for empty result, got %d", len(params))
	}
}

func TestParseArjunOutput_SingleEndpoint(t *testing.T) {
	t.Parallel()
	jsonContent := `{
		"https://example.com/search": ["q", "page", "limit", "sort"]
	}`

	tmpFile := filepath.Join(t.TempDir(), "arjun-single.json")
	if err := os.WriteFile(tmpFile, []byte(jsonContent), 0o644); err != nil {
		t.Fatal(err)
	}

	params, err := parseArjunOutput(tmpFile)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"limit", "page", "q", "sort"}
	if !reflect.DeepEqual(params, want) {
		t.Errorf("parseArjunOutput = %v, want %v", params, want)
	}
}

func TestParseArjunOutput_NonexistentFile(t *testing.T) {
	t.Parallel()
	params, err := parseArjunOutput("/tmp/does-not-exist-arjun.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(params) != 0 {
		t.Errorf("expected 0 params for nonexistent file, got %d", len(params))
	}
}

func TestParseArjunOutput_InvalidJSON(t *testing.T) {
	t.Parallel()
	tmpFile := filepath.Join(t.TempDir(), "arjun-bad.json")
	if err := os.WriteFile(tmpFile, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := parseArjunOutput(tmpFile)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseArjunOutput_DeduplicatesAcrossEndpoints(t *testing.T) {
	t.Parallel()
	jsonContent := `{
		"https://example.com/a": ["id", "name"],
		"https://example.com/b": ["name", "email"],
		"https://example.com/c": ["id", "email", "token"]
	}`

	tmpFile := filepath.Join(t.TempDir(), "arjun-dedup.json")
	if err := os.WriteFile(tmpFile, []byte(jsonContent), 0o644); err != nil {
		t.Fatal(err)
	}

	params, err := parseArjunOutput(tmpFile)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"email", "id", "name", "token"}
	if !reflect.DeepEqual(params, want) {
		t.Errorf("parseArjunOutput = %v, want %v", params, want)
	}
}
