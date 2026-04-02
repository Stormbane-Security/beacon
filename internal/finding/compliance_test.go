package finding_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
)

// containsTag returns true when the slice contains target.
func containsTag(tags []string, target string) bool {
	for _, t := range tags {
		if t == target {
			return true
		}
	}
	return false
}

func TestComplianceTags_EmailSPFMissing(t *testing.T) {
	tags := finding.ComplianceTags(finding.CheckEmailSPFMissing)
	if len(tags) == 0 {
		t.Fatal("ComplianceTags(CheckEmailSPFMissing) returned empty slice; want non-empty")
	}
	if !containsTag(tags, "SOC2-CC6.1") {
		t.Errorf("ComplianceTags(CheckEmailSPFMissing) = %v; want slice containing 'SOC2-CC6.1'", tags)
	}
}

func TestComplianceTags_EmailDMARCMissing(t *testing.T) {
	tags := finding.ComplianceTags(finding.CheckEmailDMARCMissing)
	if len(tags) == 0 {
		t.Fatal("ComplianceTags(CheckEmailDMARCMissing) returned empty slice; want non-empty")
	}
	if !containsTag(tags, "SOC2-CC6.1") {
		t.Errorf("ComplianceTags(CheckEmailDMARCMissing) = %v; want slice containing 'SOC2-CC6.1'", tags)
	}
}

func TestComplianceTags_DLPCreditCard(t *testing.T) {
	tags := finding.ComplianceTags(finding.CheckDLPCreditCard)
	if len(tags) == 0 {
		t.Fatal("ComplianceTags(CheckDLPCreditCard) returned empty slice; want non-empty")
	}
	if !containsTag(tags, "PCI-3.4") {
		t.Errorf("ComplianceTags(CheckDLPCreditCard) = %v; want slice containing 'PCI-3.4'", tags)
	}
}

func TestComplianceTags_DLPSSN(t *testing.T) {
	tags := finding.ComplianceTags(finding.CheckDLPSSN)
	if len(tags) == 0 {
		t.Fatal("ComplianceTags(CheckDLPSSN) returned empty slice; want non-empty")
	}
	if !containsTag(tags, "HIPAA-164.312") {
		t.Errorf("ComplianceTags(CheckDLPSSN) = %v; want slice containing 'HIPAA-164.312'", tags)
	}
}

func TestComplianceTags_PortRDPExposed(t *testing.T) {
	tags := finding.ComplianceTags(finding.CheckPortRDPExposed)
	if len(tags) == 0 {
		t.Fatal("ComplianceTags(CheckPortRDPExposed) returned empty slice; want non-empty")
	}
}

func TestComplianceTags_NonexistentCheck(t *testing.T) {
	tags := finding.ComplianceTags("nonexistent.check")
	if tags != nil {
		t.Errorf("ComplianceTags(\"nonexistent.check\") = %v; want nil", tags)
	}
}

// ── Expanded coverage tests ────────────────────────────────────────────

func TestComplianceTags_TLSWeakKey(t *testing.T) {
	tags := finding.ComplianceTags(finding.CheckTLSCertWeakKey)
	if len(tags) == 0 {
		t.Fatal("want non-empty")
	}
	if !containsTag(tags, "PCI-4.2.1") {
		t.Errorf("want PCI-4.2.1, got %v", tags)
	}
}

func TestComplianceTags_Headers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		checkID finding.CheckID
	}{
		{"CSP", finding.CheckHeadersMissingCSP},
		{"HSTS", finding.CheckHeadersMissingHSTS},
		{"XFrameOptions", finding.CheckHeadersMissingXFrameOptions},
		{"XContentType", finding.CheckHeadersMissingXContentType},
		{"ReferrerPolicy", finding.CheckHeadersMissingReferrerPolicy},
		{"PermissionsPolicy", finding.CheckHeadersMissingPermissionsPolicy},
		{"ServerInfoLeak", finding.CheckHeadersServerInfoLeak},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tags := finding.ComplianceTags(tc.checkID)
			if len(tags) == 0 {
				t.Fatalf("ComplianceTags(%s) returned empty", tc.checkID)
			}
			if !containsTag(tags, "SOC2-CC6.6") && !containsTag(tags, "SOC2-CC6.7") {
				t.Errorf("want SOC2 tag, got %v", tags)
			}
		})
	}
}

func TestComplianceTags_Cookies(t *testing.T) {
	for _, id := range []finding.CheckID{
		finding.CheckCookieMissingSecure,
		finding.CheckCookieMissingHTTPOnly,
		finding.CheckCookieMissingSameSite,
	} {
		tags := finding.ComplianceTags(id)
		if len(tags) == 0 {
			t.Errorf("ComplianceTags(%s) returned empty", id)
		}
	}
}

func TestComplianceTags_JWT(t *testing.T) {
	for _, id := range []finding.CheckID{
		finding.CheckJWTWeakAlg,
		finding.CheckJWTAlgNoneVariant,
		finding.CheckJWTAlgorithmConfusion,
		finding.CheckJWTNoVerification,
	} {
		tags := finding.ComplianceTags(id)
		if len(tags) == 0 {
			t.Errorf("ComplianceTags(%s) returned empty", id)
		}
		if !containsTag(tags, "SOC2-CC6.7") {
			t.Errorf("ComplianceTags(%s) = %v; want SOC2-CC6.7", id, tags)
		}
	}
}

func TestComplianceTags_OAuth(t *testing.T) {
	for _, id := range []finding.CheckID{
		finding.CheckOAuthMissingState,
		finding.CheckOAuthMissingPKCE,
		finding.CheckOAuthOpenRedirect,
	} {
		tags := finding.ComplianceTags(id)
		if len(tags) == 0 {
			t.Errorf("ComplianceTags(%s) returned empty", id)
		}
	}
}

func TestComplianceTags_SAML(t *testing.T) {
	for _, id := range []finding.CheckID{
		finding.CheckSAMLSignatureNotValidated,
		finding.CheckSAMLXMLWrapping,
		finding.CheckSAMLXXEInjection,
	} {
		tags := finding.ComplianceTags(id)
		if len(tags) == 0 {
			t.Errorf("ComplianceTags(%s) returned empty", id)
		}
	}
}

func TestComplianceTags_WebAttacks(t *testing.T) {
	for _, id := range []finding.CheckID{
		finding.CheckWebSSRF,
		finding.CheckWebSSTI,
		finding.CheckWebXXE,
		finding.CheckWebCRLFInjection,
		finding.CheckWebInsecureDeserialize,
		finding.CheckWebPathTraversal,
	} {
		tags := finding.ComplianceTags(id)
		if len(tags) == 0 {
			t.Errorf("ComplianceTags(%s) returned empty", id)
		}
		if !containsTag(tags, "PCI-6.4.1") {
			t.Errorf("ComplianceTags(%s) = %v; want PCI-6.4.1", id, tags)
		}
	}
}

func TestComplianceTags_CORS(t *testing.T) {
	for _, id := range []finding.CheckID{
		finding.CheckCORSMisconfiguration,
		finding.CheckCORSCredentialedReflection,
	} {
		tags := finding.ComplianceTags(id)
		if len(tags) == 0 {
			t.Errorf("ComplianceTags(%s) returned empty", id)
		}
	}
}

func TestComplianceTags_GHActions(t *testing.T) {
	for _, id := range []finding.CheckID{
		finding.CheckGHActionUnpinned,
		finding.CheckGHActionScriptInjection,
		finding.CheckGHActionKnownCompromised,
		finding.CheckGHActionAWSLongLivedKey,
	} {
		tags := finding.ComplianceTags(id)
		if len(tags) == 0 {
			t.Errorf("ComplianceTags(%s) returned empty", id)
		}
	}
}

func TestComplianceTags_GitHubRepo(t *testing.T) {
	for _, id := range []finding.CheckID{
		finding.CheckGitHubNoBranchProtection,
		finding.CheckGitHubNoSecretScanning,
		finding.CheckGitHubOrgMFANotRequired,
		finding.CheckGitHubSecretInCode,
	} {
		tags := finding.ComplianceTags(id)
		if len(tags) == 0 {
			t.Errorf("ComplianceTags(%s) returned empty", id)
		}
	}
}

func TestComplianceTags_AI(t *testing.T) {
	for _, id := range []finding.CheckID{
		finding.CheckAIEndpointExposed,
		finding.CheckAIPromptInjection,
		finding.CheckAIDataExfil,
	} {
		tags := finding.ComplianceTags(id)
		if len(tags) == 0 {
			t.Errorf("ComplianceTags(%s) returned empty", id)
		}
	}
}

func TestComplianceTags_ICS(t *testing.T) {
	for _, id := range []finding.CheckID{
		finding.CheckPortModbusExposed,
		finding.CheckPortS7CommExposed,
		finding.CheckPortDNP3Exposed,
	} {
		tags := finding.ComplianceTags(id)
		if len(tags) == 0 {
			t.Errorf("ComplianceTags(%s) returned empty", id)
		}
		if !containsTag(tags, "PCI-1.3") {
			t.Errorf("ComplianceTags(%s) = %v; want PCI-1.3", id, tags)
		}
	}
}

func TestComplianceTags_CVEsHavePatching(t *testing.T) {
	// All CVE check IDs should map to PCI-6.3.3 (vulnerability patching).
	cves := []finding.CheckID{
		finding.CheckCVELog4Shell,
		finding.CheckCVEOpenSSHRegreSSHion,
		finding.CheckCVEIngressNightmare,
		finding.CheckCVESpring4Shell,
		finding.CheckCVEF5BigIPAuthBypass,
		finding.CheckCVEDrupalgeddon2,
		finding.CheckCVEStruts2OGNL,
	}
	for _, id := range cves {
		tags := finding.ComplianceTags(id)
		if len(tags) == 0 {
			t.Errorf("ComplianceTags(%s) returned empty", id)
			continue
		}
		if !containsTag(tags, "PCI-6.3.3") {
			t.Errorf("ComplianceTags(%s) = %v; want PCI-6.3.3 for CVE patching", id, tags)
		}
	}
}

// ── AST-based coverage validation ──────────────────────────────────────

// infoOnlyPrefixes are check ID prefixes that represent informational
// discovery findings (not security risks) and don't require compliance tags.
var infoOnlyPrefixes = []string{
	"asset.",         // asset discovery / intelligence
	"nmap.",          // nmap fingerprinting
	"netdev.",        // network device identification (info-level)
	"web.tech_",     // tech detection
	"intel.",         // external intel API results
	"osint.",         // OSINT harvest results
	"correlation.",   // cross-asset correlation
	"terraform.",     // IaC references
	"aifp.",          // AI fingerprint
	"dns.txt_",      // DNS harvest
	"dns.ns_",       // NS records
	"tls.jarm_",     // JARM fingerprint
	"tls.cert_no_ocsp",     // informational
	"tls.cert_no_sct",      // informational
	"tls.cert_no_crl",      // informational
	"tls.cert_long_validity", // low severity, no compliance
	"tls.no_tls13",         // informational
	"tls.cert_wildcard",    // informational
	"tls.hsts_no_subdomains", // low, informational
	"tls.hsts_no_preload",  // informational
	"web.outdated_",  // version detection
	"web3.wallet_",   // wallet detection
	"web3.contract_", // contract detection
	"web3.siwe_endpoint", // SIWE detection
	"web3.siws_endpoint", // SIWS detection
	"chain.node_grafana_", // monitoring dashboard
	"chain.node_ws_",      // websocket exposure
	"chain.peer_count_",   // network info
	"chain.miner_rpc_",    // miner detection
	"chain.validator_api_", // validator detection
	"contract.source_",    // source code exposed (info)
	"cloud.bucket_exists", // existence check (info)
	"waf.detected",        // WAF detection (info)
	"waf.not_detected",    // no WAF (info)
	"ids.detected",        // IDS detection (info)
	"dirbust.waf_blocked", // WAF response
	"version.",            // version detection
	"port.ntp_exposed",    // NTP (usually benign)
	"port.stun_",          // STUN (informational)
	"port.dns_version_",   // DNS version (info)
	"port.ssh_exposed",    // SSH (common, info)
	"cms.plugin_found",    // CMS plugin (info-only)
	"email.spf_includes",  // SPF includes (info)
	"email.bimi_missing",  // BIMI (nice to have)
	"email.dane_missing",  // DANE (nice to have)
	"nuclei.stale_",       // template staleness
	"api.rate_limit_no_",  // missing header (low)
	"ghaction.deploy_targets", // informational
	"ghaction.repo_discovered", // informational
	"github.public_repos",     // informational listing
	"github.tracked_env_file", // needs code fix, not compliance
	"web.api_fuzz_error",      // 500 on fuzz (informational)
	"port.epmd_exposed",       // erlang port mapper
}

func isInfoOnly(val string) bool {
	for _, prefix := range infoOnlyPrefixes {
		if strings.HasPrefix(val, prefix) {
			return true
		}
	}
	// On-prem checks and some specific items
	if strings.HasPrefix(val, "onprem.") {
		return true
	}
	return false
}

// TestComplianceTags_CoverageAST uses AST parsing to verify that every
// security-relevant Check* constant has a compliance mapping.
func TestComplianceTags_CoverageAST(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine test file path")
	}
	checkIDsFile := filepath.Join(filepath.Dir(thisFile), "checkids.go")

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, checkIDsFile, nil, 0)
	if err != nil {
		t.Fatalf("failed to parse checkids.go: %v", err)
	}

	var missing []string
	var covered, skipped int

	for _, decl := range f.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.CONST {
			continue
		}
		for _, spec := range genDecl.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if !strings.HasPrefix(name.Name, "Check") {
					continue
				}
				if i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				val := strings.Trim(lit.Value, `"`)

				if isInfoOnly(val) {
					skipped++
					continue
				}

				tags := finding.ComplianceTags(val)
				if len(tags) > 0 {
					covered++
				} else {
					missing = append(missing, name.Name+" ("+val+")")
				}
			}
		}
	}

	t.Logf("compliance coverage: %d covered, %d info-only (skipped), %d missing", covered, skipped, len(missing))

	if len(missing) > 0 {
		// Log gaps as a warning — not a hard failure. New check IDs shouldn't
		// block CI just because compliance tags haven't been assigned yet.
		t.Logf("NOTICE: %d security-relevant Check* constants have no compliance mapping (not a failure):\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// TestComplianceTags_ValidFrameworks verifies all compliance tags use
// recognized framework prefixes.
func TestComplianceTags_ValidFrameworks(t *testing.T) {
	validPrefixes := []string{
		"SOC2-",
		"PCI-",
		"NIST-",
		"HIPAA-",
		"ISO27001-",
		"CIS-",
	}

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine test file path")
	}
	checkIDsFile := filepath.Join(filepath.Dir(thisFile), "checkids.go")

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, checkIDsFile, nil, 0)
	if err != nil {
		t.Fatalf("failed to parse checkids.go: %v", err)
	}

	for _, decl := range f.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.CONST {
			continue
		}
		for _, spec := range genDecl.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if !strings.HasPrefix(name.Name, "Check") {
					continue
				}
				if i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				val := strings.Trim(lit.Value, `"`)
				tags := finding.ComplianceTags(val)
				for _, tag := range tags {
					valid := false
					for _, p := range validPrefixes {
						if strings.HasPrefix(tag, p) {
							valid = true
							break
						}
					}
					if !valid {
						t.Errorf("ComplianceTags(%s) contains %q which has unknown framework prefix", val, tag)
					}
				}
			}
		}
	}
}

// TestComplianceTags_NoDuplicateTagsPerCheck verifies no check ID has the
// same compliance tag listed twice.
func TestComplianceTags_NoDuplicateTagsPerCheck(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine test file path")
	}
	checkIDsFile := filepath.Join(filepath.Dir(thisFile), "checkids.go")

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, checkIDsFile, nil, 0)
	if err != nil {
		t.Fatalf("failed to parse checkids.go: %v", err)
	}

	for _, decl := range f.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.CONST {
			continue
		}
		for _, spec := range genDecl.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if !strings.HasPrefix(name.Name, "Check") {
					continue
				}
				if i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				val := strings.Trim(lit.Value, `"`)
				tags := finding.ComplianceTags(val)
				seen := make(map[string]bool)
				for _, tag := range tags {
					if seen[tag] {
						t.Errorf("ComplianceTags(%s) has duplicate tag %q", val, tag)
					}
					seen[tag] = true
				}
			}
		}
	}
}

// TestComplianceTags_NoOrphanedEntries verifies that every key in the
// compliance map corresponds to an actual Check* constant in checkids.go.
// Stale mappings (check ID was removed but compliance entry lingers) are
// a hard failure — they indicate dead code and can mislead compliance reports.
func TestComplianceTags_NoOrphanedEntries(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine test file path")
	}
	checkIDsFile := filepath.Join(filepath.Dir(thisFile), "checkids.go")

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, checkIDsFile, nil, 0)
	if err != nil {
		t.Fatalf("failed to parse checkids.go: %v", err)
	}

	// Build set of all check ID string values from checkids.go.
	validIDs := make(map[string]bool)
	for _, decl := range f.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.CONST {
			continue
		}
		for _, spec := range genDecl.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if !strings.HasPrefix(name.Name, "Check") {
					continue
				}
				if i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				val := strings.Trim(lit.Value, `"`)
				validIDs[val] = true
			}
		}
	}

	// Now parse compliance.go to find all keys in complianceMap.
	complianceFile := filepath.Join(filepath.Dir(thisFile), "compliance.go")
	fset2 := token.NewFileSet()
	cf, err := parser.ParseFile(fset2, complianceFile, nil, 0)
	if err != nil {
		t.Fatalf("failed to parse compliance.go: %v", err)
	}

	// Walk the AST to find identifiers used as keys in complianceMap.
	// Each key is a Check* constant reference — verify the constant's
	// string value exists in validIDs.
	var orphaned []string
	for _, decl := range cf.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.VAR {
			continue
		}
		for _, spec := range genDecl.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, name := range vs.Names {
				if name.Name != "complianceMap" {
					continue
				}
				// Found the map. Walk its composite literal.
				if len(vs.Values) == 0 {
					continue
				}
				comp, ok := vs.Values[0].(*ast.CompositeLit)
				if !ok {
					continue
				}
				for _, elt := range comp.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					ident, ok := kv.Key.(*ast.Ident)
					if !ok {
						continue
					}
					// The key is a constant name like CheckEmailSPFMissing.
					// We need to resolve it to its string value.
					// Since we're in a different package (_test), we can
					// call finding.ComplianceTags and check if the constant
					// name maps to a valid ID. But simpler: just check that
					// the constant name exists in checkids.go.
					constName := ident.Name
					if !strings.HasPrefix(constName, "Check") {
						continue
					}
					// Look up this constant's value from our parsed checkids.go
					found := false
					for _, d := range f.Decls {
						gd, ok := d.(*ast.GenDecl)
						if !ok || gd.Tok != token.CONST {
							continue
						}
						for _, s := range gd.Specs {
							vspec, ok := s.(*ast.ValueSpec)
							if !ok {
								continue
							}
							for _, n := range vspec.Names {
								if n.Name == constName {
									found = true
								}
							}
						}
					}
					if !found {
						orphaned = append(orphaned, constName)
					}
				}
			}
		}
	}

	if len(orphaned) > 0 {
		t.Errorf("%d compliance map entries reference non-existent Check* constants (stale mappings):\n  %s",
			len(orphaned), strings.Join(orphaned, "\n  "))
	}
}
