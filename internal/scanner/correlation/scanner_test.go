package correlation

import (
	"context"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

func hasCheckID(findings []finding.Finding, id finding.CheckID) bool {
	for _, f := range findings {
		if f.CheckID == id {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// No findings → no correlations
// ---------------------------------------------------------------------------

func TestRun_NoFindings_ReturnsNil(t *testing.T) {
	s := New()
	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 findings with no input, got %d", len(results))
	}
}

// ---------------------------------------------------------------------------
// Chain 1: Open redirect + OAuth = auth bypass
// ---------------------------------------------------------------------------

func TestChain_OpenRedirectPlusOAuth(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{
			CheckID:      finding.CheckWebOpenRedirect,
			Asset:        "app.example.com",
			ProofCommand: "curl -s 'https://app.example.com/redir?url=http://evil.com'",
		},
		{
			CheckID: "oauth.missing_state",
			Asset:   "app.example.com",
		},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(results, finding.CheckCorrelationAuthBypassViaProxy) {
		t.Error("expected auth_bypass_via_proxy finding when open redirect + OAuth are present")
	}
}

func TestChain_OpenRedirectWithoutOAuth_NoFinding(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{
			CheckID: finding.CheckWebOpenRedirect,
			Asset:   "app.example.com",
		},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(results, finding.CheckCorrelationAuthBypassViaProxy) {
		t.Error("should not emit auth_bypass finding without OAuth endpoint")
	}
}

// ---------------------------------------------------------------------------
// Chain 2: XSS + CSRF = account takeover
// ---------------------------------------------------------------------------

func TestChain_XSSPlusCSRF(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{
			CheckID:      finding.CheckWebXSS,
			Asset:        "app.example.com",
			ProofCommand: "curl -s 'https://app.example.com/search?q=<script>alert(1)</script>'",
		},
		{
			CheckID:      finding.CheckWebCSRFMissing,
			Asset:        "app.example.com",
			ProofCommand: "curl -s 'https://app.example.com/settings'",
		},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(results, finding.CheckCorrelationXSSCSRFChain) {
		t.Error("expected xss_csrf_chain finding when XSS + missing CSRF are present")
	}

	// Check severity is Critical when on same asset.
	for _, f := range results {
		if f.CheckID == finding.CheckCorrelationXSSCSRFChain {
			if f.Severity != finding.SeverityCritical {
				t.Errorf("expected Critical severity for same-asset XSS+CSRF chain, got %s", f.Severity)
			}
			sameAsset, _ := f.Evidence["same_asset"].(bool)
			if !sameAsset {
				t.Error("expected same_asset=true when both findings are on the same asset")
			}
		}
	}
}

func TestChain_XSSWithoutCSRF_NoFinding(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{
			CheckID: finding.CheckWebXSS,
			Asset:   "app.example.com",
		},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(results, finding.CheckCorrelationXSSCSRFChain) {
		t.Error("should not emit xss_csrf_chain without CSRF finding")
	}
}

// ---------------------------------------------------------------------------
// Chain 3: Weak TLS + insecure cookies = session hijack
// ---------------------------------------------------------------------------

func TestChain_WeakTLSPlusInsecureCookies(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{
			CheckID:      finding.CheckTLSProtocolTLS10,
			Asset:        "app.example.com",
			ProofCommand: "nmap --script ssl-enum-ciphers -p 443 app.example.com",
		},
		{
			CheckID:      finding.CheckCookieMissingSecure,
			Asset:        "app.example.com",
			ProofCommand: "curl -sI 'https://app.example.com' | grep Set-Cookie",
		},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(results, finding.CheckCorrelationTLSSessionHijack) {
		t.Error("expected tls_session_hijack finding when weak TLS + insecure cookies are present")
	}
}

func TestChain_WeakTLSWithoutCookies_NoFinding(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{
			CheckID: finding.CheckTLSProtocolTLS10,
			Asset:   "app.example.com",
		},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(results, finding.CheckCorrelationTLSSessionHijack) {
		t.Error("should not emit tls_session_hijack without insecure cookie finding")
	}
}

// ---------------------------------------------------------------------------
// Chain 4: SSRF + cloud signals = IAM takeover
// ---------------------------------------------------------------------------

func TestChain_SSRFPlusCloudMetadata(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{
			CheckID:      finding.CheckWebSSRF,
			Asset:        "app.example.com",
			ProofCommand: "curl -s 'https://app.example.com/fetch?url=http://169.254.169.254/'",
		},
		{
			CheckID: finding.CheckCloudMetadataSSRF,
			Asset:   "app.example.com",
		},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(results, finding.CheckCorrelationCloudMetadataChain) {
		t.Error("expected cloud_metadata_chain finding when SSRF + cloud metadata are present")
	}
}

func TestChain_SSRFPlusCloudBucket(t *testing.T) {
	// SSRF + cloud bucket (as cloud infrastructure signal) should also trigger.
	s := New()
	s.SetFindings([]finding.Finding{
		{
			CheckID:      finding.CheckWebSSRF,
			Asset:        "app.example.com",
			ProofCommand: "curl -s 'https://app.example.com/fetch?url=http://internal/'",
		},
		{
			CheckID: finding.CheckCloudBucketPublic,
			Asset:   "example.com",
		},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(results, finding.CheckCorrelationCloudMetadataChain) {
		t.Error("expected cloud_metadata_chain finding when SSRF + cloud bucket exist")
	}
}

func TestChain_SSRFWithoutCloud_NoFinding(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{
			CheckID: finding.CheckWebSSRF,
			Asset:   "app.example.com",
		},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(results, finding.CheckCorrelationCloudMetadataChain) {
		t.Error("should not emit cloud_metadata_chain without cloud signals")
	}
}

// ---------------------------------------------------------------------------
// Chain 5: Info disclosure + default creds = admin access
// ---------------------------------------------------------------------------

func TestChain_InfoDisclosurePlusDefaultCreds(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{
			CheckID:      finding.CheckExposureAdminPath,
			Asset:        "admin.example.com",
			ProofCommand: "curl -sI 'https://admin.example.com/admin'",
		},
		{
			CheckID:      finding.CheckPortGrafanaDefaultCreds,
			Asset:        "monitor.example.com",
			ProofCommand: "curl -s 'https://monitor.example.com:3000/api/login'",
		},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(results, finding.CheckCorrelationCredentialReuse) {
		t.Error("expected credential_reuse finding when info disclosure + default creds are present")
	}
}

// ---------------------------------------------------------------------------
// Chain 6: Exposed .git + sensitive files = secret extraction
// ---------------------------------------------------------------------------

func TestChain_GitExposedPlusSensitiveFile(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{
			CheckID:      finding.CheckExposureGitExposed,
			Asset:        "staging.example.com",
			ProofCommand: "curl -s 'https://staging.example.com/.git/HEAD'",
		},
		{
			CheckID:      finding.CheckExposureEnvFile,
			Asset:        "staging.example.com",
			ProofCommand: "curl -s 'https://staging.example.com/.env'",
		},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(results, finding.CheckCorrelationStagingToProd) {
		t.Error("expected staging_to_prod finding when .git + .env are exposed")
	}
}

func TestChain_GitExposedAlone_NoFinding(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{
			CheckID: finding.CheckExposureGitExposed,
			Asset:   "staging.example.com",
		},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(results, finding.CheckCorrelationStagingToProd) {
		t.Error("should not emit staging_to_prod without sensitive file or staging subdomain")
	}
}

// ---------------------------------------------------------------------------
// Scanner metadata
// ---------------------------------------------------------------------------

func TestName(t *testing.T) {
	s := New()
	if s.Name() != "correlation" {
		t.Errorf("expected scanner name 'correlation', got %q", s.Name())
	}
}

// ---------------------------------------------------------------------------
// Multiple chains triggered at once
// ---------------------------------------------------------------------------

func TestMultipleChains(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		// Chain 1: Open redirect + OAuth
		{CheckID: finding.CheckWebOpenRedirect, Asset: "app.example.com"},
		{CheckID: "oauth.missing_state", Asset: "app.example.com"},
		// Chain 2: XSS + CSRF
		{CheckID: finding.CheckWebXSS, Asset: "app.example.com"},
		{CheckID: finding.CheckWebCSRFMissing, Asset: "app.example.com"},
		// Chain 3: Weak TLS + insecure cookies
		{CheckID: finding.CheckTLSWeakCipher, Asset: "app.example.com"},
		{CheckID: finding.CheckCookieMissingHTTPOnly, Asset: "app.example.com"},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(results, finding.CheckCorrelationAuthBypassViaProxy) {
		t.Error("expected auth_bypass_via_proxy chain")
	}
	if !hasCheckID(results, finding.CheckCorrelationXSSCSRFChain) {
		t.Error("expected xss_csrf_chain")
	}
	if !hasCheckID(results, finding.CheckCorrelationTLSSessionHijack) {
		t.Error("expected tls_session_hijack chain")
	}
}
