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

// TestCheckIDConstants_AST parses checkids.go and verifies every exported
// Check* constant follows the naming conventions. This replaces the need
// to manually list all 874+ check IDs in an allCheckIDs slice.
func TestCheckIDConstants_AST(t *testing.T) {
	// Find checkids.go relative to this test file.
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

	var checkConstants []string

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
				// Extract string value
				if i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				// Remove quotes from the literal value
				val := strings.Trim(lit.Value, `"`)
				checkConstants = append(checkConstants, name.Name+":"+val)
			}
		}
	}

	if len(checkConstants) == 0 {
		t.Fatal("found no Check* constants in checkids.go — parser may be broken")
	}

	t.Logf("found %d Check* constants in checkids.go", len(checkConstants))

	for _, entry := range checkConstants {
		parts := strings.SplitN(entry, ":", 2)
		constName := parts[0]
		constValue := parts[1]

		t.Run(constName, func(t *testing.T) {
			// Value must be non-empty.
			if constValue == "" {
				t.Errorf("constant %s has empty value", constName)
				return
			}

			// Value must contain exactly one dot (category.check format).
			dotCount := strings.Count(constValue, ".")
			if dotCount < 1 {
				t.Errorf("constant %s = %q has no dot — expected category.check format", constName, constValue)
				return
			}

			// Extract the prefix (category). For values like "cloud.gcp.bucket_public",
			// the category is the part before the first dot.
			dotIdx := strings.Index(constValue, ".")
			prefix := constValue[:dotIdx]

			if prefix == "" {
				t.Errorf("constant %s = %q has empty prefix", constName, constValue)
			}

			// Prefix should be lowercase and contain only [a-z0-9_]
			for _, r := range prefix {
				if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
					t.Errorf("constant %s = %q has invalid char %q in prefix %q", constName, constValue, string(r), prefix)
					break
				}
			}

			// The remainder after the prefix should also be non-empty
			remainder := constValue[dotIdx+1:]
			if remainder == "" {
				t.Errorf("constant %s = %q has empty check name after prefix", constName, constValue)
			}
		})
	}
}

// TestCheckIDConstants_ValidPrefixes verifies that all Check* constants use
// one of the known category prefixes.
func TestCheckIDConstants_ValidPrefixes(t *testing.T) {
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

	validPrefixes := map[string]bool{
		"email": true, "tls": true, "dns": true, "headers": true,
		"exposure": true, "nuclei": true, "subdomain": true, "domain": true,
		"web": true, "asset": true, "whois": true, "cloud": true,
		"js": true, "cookie": true, "csp": true, "waf": true, "ids": true,
		"dlp": true, "dirbust": true, "port": true, "graphql": true,
		"version": true, "jwt": true, "oauth": true, "ghaction": true,
		"github": true, "cicd": true, "secrets": true, "jenkins": true,
		"ai": true, "saml": true, "iam": true, "cve": true,
		"web3": true, "contract": true, "chain": true, "nmap": true,
		"intel": true, "gateway": true, "cdn": true, "cms": true,
		"exploit": true,
		"api": true, "osint": true, "supply_chain": true,
		"correlation": true, "terraform": true, "aifp": true,
		"authfuzz": true, "netdev": true, "wifi": true, "gitlab": true,
		"teamcity": true, "oidc": true, "http": true, "websocket": true,
		"bitbucket": true, "container": true, "circleci": true,
		"onprem":    true,
		"meta":      true,
		"proxy":     true,
		"cache":     true,
		"lb":        true,
		"mcp":       true,
		"auth":        true,
		"wellknown":   true,
		"http2":       true,
		"ntlm":        true,
		"ipv6":        true,
		"favicon":     true,
		"ct":          true,
		"oob":         true,
		"fingerprint": true,
		"osv":         true,
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
				dotIdx := strings.Index(val, ".")
				if dotIdx < 0 {
					continue // already caught by other test
				}
				prefix := val[:dotIdx]
				if !validPrefixes[prefix] {
					t.Errorf("constant %s = %q uses unknown prefix %q — add to validPrefixes if intentional", name.Name, val, prefix)
				}
			}
		}
	}
}

// TestCheckIDConstants_NoDuplicateValues verifies no two constants share the same string value.
func TestCheckIDConstants_NoDuplicateValues(t *testing.T) {
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

	seen := make(map[string]string) // value → first constant name

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
				if prev, exists := seen[val]; exists {
					t.Errorf("duplicate CheckID value %q: %s and %s", val, prev, name.Name)
				}
				seen[val] = name.Name
			}
		}
	}
}

// TestCheckIDConstants_AllRegistered verifies that every Check* constant
// parsed from checkids.go has a corresponding entry in the Registry.
func TestCheckIDConstants_AllRegistered(t *testing.T) {
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

	// Import the finding package to access Registry.
	// We use the values from the AST parse directly.
	var missing []string

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

				// Use the finding package's Registry (imported as finding_test).
				// finding.Registry is accessible from the _test package.
				if _, exists := finding.Registry[val]; !exists {
					missing = append(missing, name.Name+" ("+val+")")
				}
			}
		}
	}

	if len(missing) > 0 {
		t.Errorf("%d Check* constants have no Registry entry:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
}
