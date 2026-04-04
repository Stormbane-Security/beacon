// Package bigip detects and decodes F5 BIG-IP persistence cookies that leak
// internal backend server IP addresses and ports. The BIGipServer cookie
// uses a predictable encoding: the IP is stored as a reversed 32-bit integer
// and the port as a 16-bit integer with swapped bytes.
//
// Surface mode only — passive cookie inspection from normal HTTP responses.
package bigip

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/authctx"
	"github.com/stormbane-security/beacon/internal/scanner/schemedetect"
)


func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckLBBigIPCookieLeak, finding.SeverityMedium, finding.ModeSurface),
	)
}
const scannerName = "bigip"

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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/", nil)
	if err != nil {
		return nil, nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	var findings []finding.Finding

	for _, cookie := range resp.Cookies() {
		if !strings.HasPrefix(cookie.Name, "BIGipServer") {
			continue
		}
		ip, port, ok := decodeBigIPCookie(cookie.Value)
		if !ok {
			continue
		}
		poolName := strings.TrimPrefix(cookie.Name, "BIGipServer")
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckLBBigIPCookieLeak,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Title:    fmt.Sprintf("F5 BIG-IP cookie leaks internal backend %s:%d", ip, port),
			Description: fmt.Sprintf(
				"The F5 BIG-IP load balancer at %s sets a BIGipServer persistence cookie "+
					"that encodes the internal backend server address. Decoding reveals %s:%d "+
					"(pool: %q). This discloses internal network topology to attackers, aiding "+
					"further exploitation such as SSRF targeting or direct backend access.",
				asset, ip, port, poolName),
			Asset: asset,
			ProofCommand: fmt.Sprintf(
				"curl -sI '%s/' | grep -i bigipserver", base),
			Evidence: map[string]any{
				"cookie_name":  cookie.Name,
				"cookie_value": cookie.Value,
				"decoded_ip":   ip,
				"decoded_port": port,
				"pool_name":    poolName,
			},
			DiscoveredAt: time.Now(),
		})
	}

	return findings, nil
}

// decodeBigIPCookie decodes a BIGipServer cookie value like "1677787402.36895.0000"
// into an IP address and port.
//
// Format: <encoded_ip>.<encoded_port>.<route_domain>
// IP encoding: 32-bit integer with reversed byte order (little-endian stored as decimal)
// Port encoding: 16-bit integer with swapped bytes
func decodeBigIPCookie(value string) (string, int, bool) {
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return "", 0, false
	}

	hostInt, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return "", 0, false
	}

	portInt, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return "", 0, false
	}

	// IP: bytes are reversed (little-endian 32-bit)
	ip := fmt.Sprintf("%d.%d.%d.%d",
		hostInt&0xFF,
		(hostInt>>8)&0xFF,
		(hostInt>>16)&0xFF,
		(hostInt>>24)&0xFF,
	)

	// Port: bytes are swapped (big-endian 16-bit)
	port := int(((portInt & 0xFF) << 8) | ((portInt >> 8) & 0xFF))

	// Sanity check: port should be 1-65535
	if port < 1 || port > 65535 {
		return "", 0, false
	}

	return ip, port, true
}
