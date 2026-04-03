// Package csrf detects HTML forms that are missing CSRF protections.
//
// A POST form is vulnerable to CSRF when:
//  1. It has no hidden CSRF token field (common names: _token, csrf_token,
//     authenticity_token, __RequestVerificationToken, etc.)//  2. AND the response has no SameSite cookie attribute set to Strict or Lax
//
// This is a heuristic analysis — it does not attempt to submit forms. Deep mode only.
package csrf

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/authctx"
	"golang.org/x/net/html"
)


func init() {
	scan.Register(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	})
}
const scannerName = "csrf"

// Known CSRF token field names used by popular frameworks.
var csrfFieldNames = map[string]bool{
	"_token":                        true, // Laravel
	"csrf_token":                    true, // Flask-WTF, Django
	"csrfmiddlewaretoken":           true, // Django
	"authenticity_token":            true, // Rails
	"__requestverificationtoken":    true, // ASP.NET MVC
	"_csrf":                         true, // Express csurf
	"csrf":                          true, // generic
	"xsrf_token":                    true, // AngularJS
	"_xsrf":                         true, // Tornado
	"antiforgerytoken":              true, // ASP.NET
	"__antixsrftoken":               true, // ASP.NET alternative
	"nonce":                         true, // WordPress
	"_wpnonce":                      true, // WordPress
	"token":                         true, // generic (only matched as hidden input)
	"form_build_id":                 true, // Drupal
	"form_token":                    true, // Drupal
}

// Scanner checks for CSRF token absence on POST forms.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

// Run scans the target for forms missing CSRF protection.
// Only runs in deep mode because it actively fetches and parses pages.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep && scanType != module.ScanAuthorized {
		return nil, nil
	}

	client := authctx.HTTPClient(ctx)
	// Override transport for TLS skip and redirect control
	client = &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
		Jar: client.Jar,
	}

	// Probe paths likely to contain forms
	paths := []string{
		"/", "/login", "/register", "/signup", "/contact",
		"/account", "/settings", "/profile", "/admin",
		"/password/reset", "/forgot-password",
	}

	var findings []finding.Finding
	seen := make(map[string]bool) // dedupe by path+action

	for _, path := range paths {
		if ctx.Err() != nil {
			break
		}

		for _, scheme := range []string{"https", "http"} {
			url := scheme + "://" + asset + path
			forms, cookies, err := fetchForms(ctx, client, url)
			if err != nil {
				continue
			}

			hasSameSite := hasSameSiteCookie(cookies)

			for _, f := range forms {
				if !f.isPost {
					continue
				}
				if f.hasCSRFToken {
					continue
				}
				if hasSameSite {
					continue
				}

				key := path + "|" + f.action
				if seen[key] {
					continue
				}
				seen[key] = true

				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckWebCSRFMissing,
					Module:   "surface",
					Scanner:  scannerName,
					Severity: finding.SeverityMedium,
					Title:    fmt.Sprintf("POST form at %s missing CSRF token", path),
					Description: fmt.Sprintf(
						"A <form method=POST> at %s (action=%q) has no CSRF token hidden field "+
							"and no SameSite cookie attribute. This form may be vulnerable to "+
							"cross-site request forgery attacks.",
						url, f.action),
					Asset: asset,
					Evidence: map[string]any{
						"path":         path,
						"form_action":  f.action,
						"has_samesite": false,
						"fields":       f.fieldNames,
					},
					ProofCommand: fmt.Sprintf(
						`curl -s '%s' | grep -i '<form.*method.*post'`,
						url),
					DiscoveredAt: time.Now(),
				})
			}

			// If HTTPS works, skip HTTP for this path
			if err == nil {
				break
			}
		}
	}

	return findings, nil
}

type formInfo struct {
	action       string
	isPost       bool
	hasCSRFToken bool
	fieldNames   []string
}

// fetchForms fetches the given URL and parses all <form> elements.
func fetchForms(ctx context.Context, client *http.Client, url string) ([]formInfo, []*http.Cookie, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; beacon-csrf-scanner)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, resp.Cookies(), fmt.Errorf("status %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") && !strings.Contains(ct, "application/xhtml") {
		return nil, resp.Cookies(), fmt.Errorf("not HTML: %s", ct)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // 2MB limit
	if err != nil {
		return nil, resp.Cookies(), err
	}

	forms := parseForms(string(body))
	return forms, resp.Cookies(), nil
}

// parseForms extracts form metadata from raw HTML.
func parseForms(body string) []formInfo {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil
	}

	var forms []formInfo
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			fi := parseFormNode(n)
			forms = append(forms, fi)
			return // don't recurse inside form — we already parsed it
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return forms
}

// parseFormNode extracts method, action, and input field info from a form node.
func parseFormNode(formNode *html.Node) formInfo {
	fi := formInfo{}

	for _, attr := range formNode.Attr {
		switch strings.ToLower(attr.Key) {
		case "method":
			fi.isPost = strings.EqualFold(attr.Val, "post")
		case "action":
			fi.action = attr.Val
		}
	}

	// Walk children looking for input fields
	var walkInputs func(*html.Node)
	walkInputs = func(n *html.Node) {
		if n.Type == html.ElementNode && (n.Data == "input" || n.Data == "meta") {
			name := ""
			inputType := ""
			for _, attr := range n.Attr {
				switch strings.ToLower(attr.Key) {
				case "name":
					name = strings.ToLower(attr.Val)
				case "type":
					inputType = strings.ToLower(attr.Val)
				}
			}
			if name != "" {
				fi.fieldNames = append(fi.fieldNames, name)
			}
			if inputType == "hidden" && csrfFieldNames[name] {
				fi.hasCSRFToken = true
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walkInputs(c)
		}
	}
	walkInputs(formNode)

	return fi
}

// hasSameSiteCookie checks if any response cookie has SameSite=Strict or SameSite=Lax.
func hasSameSiteCookie(cookies []*http.Cookie) bool {
	for _, c := range cookies {
		if c.SameSite == http.SameSiteStrictMode || c.SameSite == http.SameSiteLaxMode {
			return true
		}
	}
	return false
}
