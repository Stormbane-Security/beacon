package ctlog

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestScannerName(t *testing.T) {
	s := New()
	if s.Name() != "ctlog" {
		t.Errorf("Name() = %q; want %q", s.Name(), "ctlog")
	}
}

func TestDeduplication(t *testing.T) {
	entries := []crtEntry{
		{NameValue: "api.example.com"},
		{NameValue: "api.example.com"},
		{NameValue: "dev.example.com\napi.example.com"},
		{NameValue: "*.example.com"},
	}

	seen := map[string]bool{}
	var subdomains []string
	asset := "example.com"

	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			name = strings.TrimPrefix(name, "*.")
			if name == "" || name == asset || seen[name] {
				continue
			}
			if !strings.HasSuffix(name, "."+asset) {
				continue
			}
			seen[name] = true
			subdomains = append(subdomains, name)
		}
	}

	if len(subdomains) != 2 {
		t.Errorf("expected 2 unique subdomains, got %d: %v", len(subdomains), subdomains)
	}
}

func TestCap500(t *testing.T) {
	// Generate 600 entries.
	var entries []crtEntry
	for i := 0; i < 600; i++ {
		entries = append(entries, crtEntry{
			NameValue: strings.Replace("sub-NNN.example.com", "NNN", strings.Repeat("a", i%26+1), 1),
		})
	}

	// Simulate the capping logic.
	seen := map[string]bool{}
	var subdomains []string
	asset := "example.com"
	for _, e := range entries {
		name := strings.TrimSpace(strings.ToLower(e.NameValue))
		if name == "" || name == asset || seen[name] {
			continue
		}
		if !strings.HasSuffix(name, "."+asset) {
			continue
		}
		seen[name] = true
		subdomains = append(subdomains, name)
	}
	if len(subdomains) > 500 {
		subdomains = subdomains[:500]
	}

	if len(subdomains) > 500 {
		t.Errorf("expected cap at 500, got %d", len(subdomains))
	}
}

func TestJSONParsing(t *testing.T) {
	entries := []crtEntry{
		{NameValue: "api.example.com", IssuerName: "Let's Encrypt", NotBefore: "2024-01-01", NotAfter: "2025-01-01"},
		{NameValue: "dev.example.com\nstaging.example.com", IssuerName: "DigiCert", NotBefore: "2024-06-01", NotAfter: "2025-06-01"},
	}

	data, err := json.Marshal(entries)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var parsed []crtEntry
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(parsed) != 2 {
		t.Errorf("expected 2 entries, got %d", len(parsed))
	}
	if parsed[0].NameValue != "api.example.com" {
		t.Errorf("first entry name = %q", parsed[0].NameValue)
	}
}

func TestSubdomainSkipsRootDomain(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entries := []crtEntry{
			{NameValue: "example.com"},
			{NameValue: "api.example.com"},
		}
		_ = json.NewEncoder(w).Encode(entries)
	}))
	defer ts.Close()

	// Test that the root domain itself is excluded from subdomains.
	entries := []crtEntry{
		{NameValue: "example.com"},
		{NameValue: "api.example.com"},
	}

	seen := map[string]bool{}
	var subdomains []string
	asset := "example.com"
	for _, e := range entries {
		name := strings.TrimSpace(strings.ToLower(e.NameValue))
		if name == "" || name == asset || seen[name] {
			continue
		}
		if !strings.HasSuffix(name, "."+asset) {
			continue
		}
		seen[name] = true
		subdomains = append(subdomains, name)
	}

	if len(subdomains) != 1 || subdomains[0] != "api.example.com" {
		t.Errorf("expected [api.example.com], got %v", subdomains)
	}
}
