package web3defi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

func TestScanner_Name(t *testing.T) {
	s := New()
	if s.Name() != "web3defi" {
		t.Errorf("expected scanner name %q, got %q", "web3defi", s.Name())
	}
}

func TestDefiAdminEndpointDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/pools" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"pools": []map[string]any{
					{"name": "ETH-USDC", "tvl": "1500000", "apy": "12.5", "liquidity": "500000"},
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckWeb3DefiAdminExposed {
			found = true
			if f.Severity != finding.SeverityCritical {
				t.Errorf("expected Critical severity, got %s", f.Severity)
			}
			if f.ProofCommand == "" {
				t.Error("ProofCommand should be set")
			}
			break
		}
	}
	if !found {
		t.Fatal("expected web3.defi_admin_exposed finding for /admin/pools")
	}
}

func TestNFTMetadataEndpointDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metadata/1" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"name":        "Cool NFT #1",
				"description": "A very cool NFT",
				"image":       "ipfs://QmXyz123/1.png",
				"attributes": []map[string]any{
					{"trait_type": "Background", "value": "Blue"},
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckWeb3NFTMetadataExposed {
			found = true
			if f.Severity != finding.SeverityMedium {
				t.Errorf("expected Medium severity, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected web3.nft_metadata_exposed finding for /metadata/1")
	}
}

func TestDefiContractInPageSource(t *testing.T) {
	// Page source contains Uniswap V2 Router address.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprintln(w, `<!DOCTYPE html><html><body>
				<script>
					const ROUTER = "0x7a250d5630b4cf539739df2c5dacb4c659f2488d";
					const FACTORY = "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f";
				</script>
			</body></html>`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckWeb3DefiAdminExposed && strings.Contains(f.Title, "Uniswap") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected web3.defi_admin_exposed finding for Uniswap V2 Router address in page source")
	}
}

func TestAllEndpoints404_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when all endpoints return 404, got %d", len(findings))
	}
}

func TestHTMLResponse_NotFalsePositive(t *testing.T) {
	// SPA returns 200 with HTML for all paths.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintln(w, `<!DOCTYPE html><html><body>SPA fallback</body></html>`)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckWeb3DefiAdminExposed && f.Evidence["path"] != nil {
			t.Errorf("must not emit DeFi admin finding for HTML fallback response: %s", f.Title)
		}
	}
}

func TestSingleSignalNotEnough(t *testing.T) {
	// Endpoint returns JSON with only one signal match - should not trigger.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/pools" {
			w.Header().Set("Content-Type", "application/json")
			// Only "pool" matches, need at least 2.
			_, _ = fmt.Fprintln(w, `{"pool": "test", "unrelated": "data"}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckWeb3DefiAdminExposed && f.Evidence["path"] == "/admin/pools" {
			t.Error("must not emit DeFi admin finding when only one signal matches")
		}
	}
}

func TestGovernanceEndpointDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/governance/proposals" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"proposals": []map[string]any{
					{"id": 1, "title": "Upgrade to V3", "vote": "active", "quorum": "50%"},
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(t.Context(), asset, module.ScanSurface)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.CheckID == finding.CheckWeb3DefiAdminExposed {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected web3.defi_admin_exposed finding for governance API")
	}
}
