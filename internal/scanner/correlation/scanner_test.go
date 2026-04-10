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
// Chain 7: CORS + XSS + missing HttpOnly = session hijack
// ---------------------------------------------------------------------------

func TestChain_SessionHijack_CORSPlusXSSPlusNoHttpOnly(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{CheckID: finding.CheckCORSMisconfiguration, Asset: "app.example.com", ProofCommand: "curl -sI -H 'Origin: https://evil.com' https://app.example.com"},
		{CheckID: finding.CheckWebXSS, Asset: "app.example.com", ProofCommand: "curl -s 'https://app.example.com/?q=<script>'"},
		{CheckID: finding.CheckCookieMissingHTTPOnly, Asset: "app.example.com", ProofCommand: "curl -sI https://app.example.com"},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(results, finding.CheckCorrelationSessionHijackChain) {
		t.Error("expected session_hijack_chain when CORS + XSS + missing HttpOnly are present")
	}
	for _, f := range results {
		if f.CheckID == finding.CheckCorrelationSessionHijackChain {
			if f.Severity != finding.SeverityCritical {
				t.Errorf("expected Critical severity, got %s", f.Severity)
			}
			if f.ChainDepth != 3 {
				t.Errorf("expected ChainDepth 3, got %d", f.ChainDepth)
			}
			if f.EnabledBy == "" {
				t.Error("expected EnabledBy to be set")
			}
		}
	}
}

func TestChain_SessionHijack_MissingXSS_NoFinding(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{CheckID: finding.CheckCORSMisconfiguration, Asset: "app.example.com"},
		{CheckID: finding.CheckCookieMissingHTTPOnly, Asset: "app.example.com"},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(results, finding.CheckCorrelationSessionHijackChain) {
		t.Error("should not emit session_hijack_chain without XSS")
	}
}

func TestChain_SessionHijack_MissingCORS_NoFinding(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{CheckID: finding.CheckWebXSS, Asset: "app.example.com"},
		{CheckID: finding.CheckCookieMissingHTTPOnly, Asset: "app.example.com"},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(results, finding.CheckCorrelationSessionHijackChain) {
		t.Error("should not emit session_hijack_chain without CORS misconfig")
	}
}

func TestChain_SessionHijack_CredentialedReflection(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{CheckID: finding.CheckCORSCredentialedReflection, Asset: "api.example.com"},
		{CheckID: finding.CheckWebReflectedXSS, Asset: "api.example.com"},
		{CheckID: finding.CheckCookieMissingHTTPOnly, Asset: "api.example.com"},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(results, finding.CheckCorrelationSessionHijackChain) {
		t.Error("expected session_hijack_chain with credentialed CORS + reflected XSS")
	}
}

// ---------------------------------------------------------------------------
// Chain 8: Credential theft (env + DB or git + secrets)
// ---------------------------------------------------------------------------

func TestChain_CredentialTheft_EnvPlusDatabase(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{CheckID: finding.CheckExposureEnvFile, Asset: "app.example.com", ProofCommand: "curl -s https://app.example.com/.env"},
		{CheckID: finding.CheckPortDatabaseExposed, Asset: "db.example.com", ProofCommand: "nmap -p 3306 db.example.com"},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(results, finding.CheckCorrelationCredentialTheftChain) {
		t.Error("expected credential_theft_chain when .env + database exposed")
	}
	for _, f := range results {
		if f.CheckID == finding.CheckCorrelationCredentialTheftChain {
			variant, _ := f.Evidence["chain_variant"].(string)
			if variant != "env_plus_database" {
				t.Errorf("expected env_plus_database variant, got %q", variant)
			}
		}
	}
}

func TestChain_CredentialTheft_GitPlusSecrets(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{CheckID: finding.CheckExposureGitExposed, Asset: "staging.example.com", ProofCommand: "curl -s https://staging.example.com/.git/HEAD"},
		{CheckID: finding.CheckExposureSensitiveFile, Asset: "staging.example.com", ProofCommand: "curl -s https://staging.example.com/config.yml"},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(results, finding.CheckCorrelationCredentialTheftChain) {
		t.Error("expected credential_theft_chain when .git + sensitive file exposed")
	}
	for _, f := range results {
		if f.CheckID == finding.CheckCorrelationCredentialTheftChain {
			variant, _ := f.Evidence["chain_variant"].(string)
			if variant != "git_plus_secrets" {
				t.Errorf("expected git_plus_secrets variant, got %q", variant)
			}
		}
	}
}

func TestChain_CredentialTheft_EnvAlone_NoFinding(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{CheckID: finding.CheckExposureEnvFile, Asset: "app.example.com"},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(results, finding.CheckCorrelationCredentialTheftChain) {
		t.Error("should not emit credential_theft_chain with .env alone")
	}
}

// ---------------------------------------------------------------------------
// Chain 9: Full compromise (SQLi + DB or SSRF + cloud metadata)
// ---------------------------------------------------------------------------

func TestChain_FullCompromise_SQLiPlusDatabase(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{CheckID: finding.CheckWebSQLi, Asset: "app.example.com", ProofCommand: "sqlmap -u 'https://app.example.com/search?q=test'"},
		{CheckID: finding.CheckPortDatabaseExposed, Asset: "db.example.com", ProofCommand: "nmap -p 3306 db.example.com"},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(results, finding.CheckCorrelationFullCompromiseChain) {
		t.Error("expected full_compromise_chain when SQLi + database exposed")
	}
	for _, f := range results {
		if f.CheckID == finding.CheckCorrelationFullCompromiseChain {
			variant, _ := f.Evidence["chain_variant"].(string)
			if variant != "sqli_plus_database" {
				t.Errorf("expected sqli_plus_database variant, got %q", variant)
			}
			if f.Severity != finding.SeverityCritical {
				t.Errorf("expected Critical severity, got %s", f.Severity)
			}
		}
	}
}

func TestChain_FullCompromise_SSRFPlusCloudMetadata(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{CheckID: finding.CheckWebSSRF, Asset: "app.example.com", ProofCommand: "curl 'https://app.example.com/fetch?url=http://169.254.169.254/'"},
		{CheckID: finding.CheckCloudMetadataSSRF, Asset: "app.example.com", ProofCommand: "curl http://169.254.169.254/latest/meta-data/"},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(results, finding.CheckCorrelationFullCompromiseChain) {
		t.Error("expected full_compromise_chain when SSRF + cloud metadata confirmed")
	}
	for _, f := range results {
		if f.CheckID == finding.CheckCorrelationFullCompromiseChain {
			variant, _ := f.Evidence["chain_variant"].(string)
			if variant != "ssrf_plus_cloud_takeover" {
				t.Errorf("expected ssrf_plus_cloud_takeover variant, got %q", variant)
			}
		}
	}
}

func TestChain_FullCompromise_SQLiAlone_NoFinding(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{CheckID: finding.CheckWebSQLi, Asset: "app.example.com"},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(results, finding.CheckCorrelationFullCompromiseChain) {
		t.Error("should not emit full_compromise_chain with SQLi alone")
	}
}

// ---------------------------------------------------------------------------
// Chain 10: Auth bypass (JWT weak + no rotation or default creds + admin)
// ---------------------------------------------------------------------------

func TestChain_AuthBypass_JWTWeakPlusNoRotation(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{CheckID: finding.CheckJWTWeakAlg, Asset: "api.example.com", ProofCommand: "jwt_tool -t https://api.example.com"},
		{CheckID: finding.CheckJWTReplayMissing, Asset: "api.example.com", ProofCommand: "# replay token after expiry"},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(results, finding.CheckCorrelationAuthBypassChain) {
		t.Error("expected auth_bypass_chain when JWT weak alg + no rotation")
	}
	for _, f := range results {
		if f.CheckID == finding.CheckCorrelationAuthBypassChain {
			variant, _ := f.Evidence["chain_variant"].(string)
			if variant != "jwt_weak_plus_no_rotation" {
				t.Errorf("expected jwt_weak_plus_no_rotation variant, got %q", variant)
			}
		}
	}
}

func TestChain_AuthBypass_DefaultCredsPlusAdmin(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{CheckID: finding.CheckPortGrafanaDefaultCreds, Asset: "monitor.example.com", ProofCommand: "curl -u admin:admin https://monitor.example.com:3000/api/org"},
		{CheckID: finding.CheckExposureAdminPath, Asset: "monitor.example.com", ProofCommand: "curl -sI https://monitor.example.com/admin"},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(results, finding.CheckCorrelationAuthBypassChain) {
		t.Error("expected auth_bypass_chain when default creds + admin panel")
	}
	for _, f := range results {
		if f.CheckID == finding.CheckCorrelationAuthBypassChain {
			variant, _ := f.Evidence["chain_variant"].(string)
			if variant != "default_creds_plus_admin" {
				t.Errorf("expected default_creds_plus_admin variant, got %q", variant)
			}
		}
	}
}

func TestChain_AuthBypass_JWTWeakAlone_NoFinding(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{CheckID: finding.CheckJWTWeakAlg, Asset: "api.example.com"},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(results, finding.CheckCorrelationAuthBypassChain) {
		t.Error("should not emit auth_bypass_chain with JWT weak alone")
	}
}

func TestChain_AuthBypass_AlgNoneVariant(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{CheckID: finding.CheckJWTAlgNoneVariant, Asset: "api.example.com"},
		{CheckID: finding.CheckJWTLongExpiry, Asset: "api.example.com"},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(results, finding.CheckCorrelationAuthBypassChain) {
		t.Error("expected auth_bypass_chain with alg:none variant + long expiry")
	}
}

// ---------------------------------------------------------------------------
// Chain 11: Cache poisoning (host injection + cache or unkeyed + XSS)
// ---------------------------------------------------------------------------

func TestChain_CachePoisoning_HostInjectionPlusCache(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{CheckID: finding.CheckHostHeaderInjection, Asset: "app.example.com", ProofCommand: "curl -sI -H 'Host: evil.com' https://app.example.com"},
		{CheckID: finding.CheckCacheBehaviorDetected, Asset: "app.example.com", ProofCommand: "curl -sI https://app.example.com | grep -i x-cache"},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(results, finding.CheckCorrelationCachePoisoningChain) {
		t.Error("expected cache_poisoning_chain when host injection + cache detected")
	}
	for _, f := range results {
		if f.CheckID == finding.CheckCorrelationCachePoisoningChain {
			variant, _ := f.Evidence["chain_variant"].(string)
			if variant != "host_injection_plus_cache" {
				t.Errorf("expected host_injection_plus_cache variant, got %q", variant)
			}
		}
	}
}

func TestChain_CachePoisoning_UnkeyedPlusXSS(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{CheckID: finding.CheckCachePoisonUnkeyed, Asset: "cdn.example.com", ProofCommand: "curl -sI -H 'X-Forwarded-Host: evil.com' https://cdn.example.com"},
		{CheckID: finding.CheckWebXSS, Asset: "cdn.example.com", ProofCommand: "curl -s 'https://cdn.example.com/?q=<script>'"},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(results, finding.CheckCorrelationCachePoisoningChain) {
		t.Error("expected cache_poisoning_chain when unkeyed header + XSS")
	}
	for _, f := range results {
		if f.CheckID == finding.CheckCorrelationCachePoisoningChain {
			variant, _ := f.Evidence["chain_variant"].(string)
			if variant != "unkeyed_header_plus_xss" {
				t.Errorf("expected unkeyed_header_plus_xss variant, got %q", variant)
			}
		}
	}
}

func TestChain_CachePoisoning_HostInjectionAlone_NoFinding(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{CheckID: finding.CheckHostHeaderInjection, Asset: "app.example.com"},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(results, finding.CheckCorrelationCachePoisoningChain) {
		t.Error("should not emit cache_poisoning_chain with host injection alone")
	}
}

// ---------------------------------------------------------------------------
// Chain 12: Lateral movement (unauthenticated service + web vuln)
// ---------------------------------------------------------------------------

func TestChain_LateralMovement_RedisPlusSSRF(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{CheckID: finding.CheckPortRedisUnauth, Asset: "redis.example.com", ProofCommand: "redis-cli -h redis.example.com ping"},
		{CheckID: finding.CheckWebSSRF, Asset: "app.example.com", ProofCommand: "curl 'https://app.example.com/fetch?url=http://redis.example.com:6379/'"},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(results, finding.CheckCorrelationLateralMovementChain) {
		t.Error("expected lateral_movement_chain when Redis unauth + SSRF")
	}
	for _, f := range results {
		if f.CheckID == finding.CheckCorrelationLateralMovementChain {
			if f.Severity != finding.SeverityCritical {
				t.Errorf("expected Critical severity, got %s", f.Severity)
			}
		}
	}
}

func TestChain_LateralMovement_ElasticsearchPlusSQLi(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{CheckID: finding.CheckPortElasticsearchUnauth, Asset: "es.example.com"},
		{CheckID: finding.CheckWebSQLi, Asset: "app.example.com"},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(results, finding.CheckCorrelationLateralMovementChain) {
		t.Error("expected lateral_movement_chain when Elasticsearch unauth + SQLi")
	}
}

func TestChain_LateralMovement_UnauthServiceAlone_NoFinding(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{CheckID: finding.CheckPortRedisUnauth, Asset: "redis.example.com"},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(results, finding.CheckCorrelationLateralMovementChain) {
		t.Error("should not emit lateral_movement_chain with unauth service alone")
	}
}

// ---------------------------------------------------------------------------
// Chain 13: DNS rebinding + internal services
// ---------------------------------------------------------------------------

func TestChain_DNSRebinding_PlusUnauthService(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{CheckID: finding.CheckDNSRebindHostUnvalidated, Asset: "app.example.com", ProofCommand: "curl -H 'Host: internal' https://app.example.com"},
		{CheckID: finding.CheckPortRedisUnauth, Asset: "internal.example.com", ProofCommand: "redis-cli -h internal.example.com ping"},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(results, finding.CheckCorrelationDNSRebindingChain) {
		t.Error("expected dns_rebinding_chain when DNS rebinding + unauth service")
	}
	for _, f := range results {
		if f.CheckID == finding.CheckCorrelationDNSRebindingChain {
			if f.Severity != finding.SeverityCritical {
				t.Errorf("expected Critical severity, got %s", f.Severity)
			}
			if f.ChainDepth != 2 {
				t.Errorf("expected ChainDepth 2, got %d", f.ChainDepth)
			}
		}
	}
}

func TestChain_DNSRebinding_PlusDatabase(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{CheckID: finding.CheckDNSRebindingVulnerable, Asset: "app.example.com"},
		{CheckID: finding.CheckPortDatabaseExposed, Asset: "db.example.com"},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(results, finding.CheckCorrelationDNSRebindingChain) {
		t.Error("expected dns_rebinding_chain when DNS rebinding vulnerable + database exposed")
	}
}

func TestChain_DNSRebinding_PlusSSRF(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{CheckID: finding.CheckDNSRebindHostUnvalidated, Asset: "app.example.com"},
		{CheckID: finding.CheckWebSSRF, Asset: "app.example.com"},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCheckID(results, finding.CheckCorrelationDNSRebindingChain) {
		t.Error("expected dns_rebinding_chain when DNS rebinding + SSRF")
	}
}

func TestChain_DNSRebinding_Alone_NoFinding(t *testing.T) {
	s := New()
	s.SetFindings([]finding.Finding{
		{CheckID: finding.CheckDNSRebindHostUnvalidated, Asset: "app.example.com"},
	})

	results, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasCheckID(results, finding.CheckCorrelationDNSRebindingChain) {
		t.Error("should not emit dns_rebinding_chain without internal service indicators")
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
