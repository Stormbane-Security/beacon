// Package iisversion performs deep IIS version fingerprinting beyond the
// Server header.
//
// IIS administrators often strip the version from the Server header, but
// detailed version information leaks through:
//   - Custom error pages (e.g., /a.aspx returns IIS-branded 404 with version)
//   - ASP.NET trace endpoint (/trace.axd)
//   - IIS management paths (/iisstart.htm, /iishelp)
//   - X-AspNet-Version / X-AspNetMvc-Version headers on .aspx routes
//   - Custom 404 error page content containing IIS version strings
//
// Surface mode only — reads error pages passively served by the web server.
package iisversion

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/authctx"
	"github.com/stormbane-security/beacon/internal/scanner/schemedetect"
)

const scannerName = "iisversion"

// probePaths that reveal IIS version information.
var probePaths = []string{
	"/iisstart.htm",
	"/iishelp/",
	"/trace.axd",
	"/" + "beacon-nonexistent-7f3a.aspx", // trigger ASP.NET error page
	"/" + "beacon-nonexistent-7f3a.asp",   // trigger classic ASP error page
	"/aspnet_client/",
}

// iisVersionPatterns match IIS version strings in response bodies.
var iisVersionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`Microsoft-IIS/(\d+\.\d+)`),
	regexp.MustCompile(`IIS\s+(\d+\.\d+)`),
	regexp.MustCompile(`Internet\s+Information\s+Services\s+(\d+(?:\.\d+)?)`),
	regexp.MustCompile(`Version\s+Information.*Microsoft\s+\.NET\s+Framework\s+Version:([0-9.]+)`),
	regexp.MustCompile(`X-AspNet-Version:\s*([0-9.]+)`),
}

// aspnetVersionPatterns match ASP.NET version strings.
var aspnetVersionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`ASP\.NET\s+Version:([0-9.]+)`),
	regexp.MustCompile(`\.NET\s+(?:CLR|Framework)\s+Version:?\s*([0-9.]+)`),
}

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanSurface && scanType != module.ScanDeep && scanType != module.ScanAuthorized {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if c := authctx.HTTPClient(ctx); c != nil {
		client = c
	}

	base := schemedetect.Base(ctx, client, asset)

	// First check if this looks like an IIS server at all.
	if !looksLikeIIS(ctx, client, base) {
		return nil, nil
	}

	// Probe IIS-specific paths for version leakage.
	var iisVersion string
	var aspnetVersion string
	var leakPaths []string

	for _, path := range probePaths {
		if ctx.Err() != nil {
			break
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner)")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		bodyStr := string(body)

		// Check response headers for ASP.NET version.
		if v := resp.Header.Get("X-AspNet-Version"); v != "" && aspnetVersion == "" {
			aspnetVersion = v
			leakPaths = append(leakPaths, path+" (X-AspNet-Version header)")
		}
		if v := resp.Header.Get("X-AspNetMvc-Version"); v != "" {
			leakPaths = append(leakPaths, path+" (X-AspNetMvc-Version header)")
		}

		// Check body for IIS version strings.
		for _, re := range iisVersionPatterns {
			if m := re.FindStringSubmatch(bodyStr); len(m) > 1 {
				if iisVersion == "" || len(m[1]) > len(iisVersion) {
					iisVersion = m[1]
					leakPaths = append(leakPaths, path)
				}
			}
		}

		// Check body for ASP.NET version strings.
		for _, re := range aspnetVersionPatterns {
			if m := re.FindStringSubmatch(bodyStr); len(m) > 1 {
				if aspnetVersion == "" {
					aspnetVersion = m[1]
					leakPaths = append(leakPaths, path)
				}
			}
		}
	}

	if iisVersion == "" && aspnetVersion == "" {
		return nil, nil
	}

	evidence := map[string]any{
		"leak_paths": leakPaths,
	}
	if iisVersion != "" {
		evidence["iis_version"] = iisVersion
	}
	if aspnetVersion != "" {
		evidence["aspnet_version"] = aspnetVersion
	}

	versionStr := ""
	if iisVersion != "" {
		versionStr = "IIS/" + iisVersion
	}
	if aspnetVersion != "" {
		if versionStr != "" {
			versionStr += ", "
		}
		versionStr += "ASP.NET " + aspnetVersion
	}

	return []finding.Finding{{
		CheckID:  finding.CheckWebIISVersionLeak,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityMedium,
		Title:    fmt.Sprintf("IIS version information leaked via error pages: %s", versionStr),
		Description: fmt.Sprintf(
			"The IIS server at %s leaks detailed version information (%s) through error pages "+
				"or debug endpoints. This reveals the exact IIS and ASP.NET versions, enabling "+
				"targeted CVE exploitation. Strip version headers, customize error pages, and "+
				"disable trace/debug endpoints in production.",
			asset, versionStr),
		Asset: asset,
		ProofCommand: fmt.Sprintf(
			"curl -sI '%s/beacon-nonexistent-7f3a.aspx' | grep -i 'x-aspnet\\|x-powered\\|server'",
			base),
		Evidence:     evidence,
		DiscoveredAt: time.Now(),
	}}, nil
}

// looksLikeIIS checks if the root page has IIS indicators.
func looksLikeIIS(ctx context.Context, client *http.Client, base string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, base+"/", nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner)")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()

	server := strings.ToLower(resp.Header.Get("Server"))
	if strings.Contains(server, "iis") || strings.Contains(server, "microsoft") {
		return true
	}
	// Check for ASP.NET headers (IIS without Server header).
	if resp.Header.Get("X-AspNet-Version") != "" || resp.Header.Get("X-Powered-By") == "ASP.NET" {
		return true
	}
	return false
}
