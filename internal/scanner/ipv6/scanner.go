// Package ipv6 checks for IPv6 reachability by resolving AAAA records
// and probing for HTTP services on the IPv6 address. Many organizations
// deploy IPv6 without the same security controls as IPv4.
package ipv6

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan"
)

func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckIPv6AAAAFound, finding.SeverityInfo, finding.ModeSurface),
		scan.Check(finding.CheckIPv6ServiceOpen, finding.SeverityInfo, finding.ModeSurface),
	)
}

const scannerName = "ipv6"

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	// Resolve AAAA records.
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, asset)
	if err != nil {
		return nil, nil
	}

	var ipv6Addrs []string
	for _, ip := range ips {
		if ip.IP.To4() == nil && ip.IP.To16() != nil {
			ipv6Addrs = append(ipv6Addrs, ip.IP.String())
		}
	}

	if len(ipv6Addrs) == 0 {
		return nil, nil
	}

	var findings []finding.Finding
	now := time.Now()

	findings = append(findings, finding.Finding{
		CheckID:  finding.CheckIPv6AAAAFound,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityInfo,
		Asset:    asset,
		Title:    fmt.Sprintf("IPv6 AAAA record(s) found for %s", asset),
		Description: fmt.Sprintf(
			"%s has %d AAAA record(s): %v. IPv6-reachable services may have different "+
				"firewall rules, WAF coverage, or access controls than their IPv4 counterparts.",
			asset, len(ipv6Addrs), ipv6Addrs,
		),
		Evidence: map[string]any{
			"ipv6_addresses": ipv6Addrs,
		},
		ProofCommand: fmt.Sprintf("dig AAAA %s +short", asset),
		DiscoveredAt: now,
	})

	// Probe HTTP(S) on each IPv6 address.
	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, addr := range ipv6Addrs {
		for _, scheme := range []string{"https", "http"} {
			port := "443"
			if scheme == "http" {
				port = "80"
			}

			// Create a custom transport to connect directly to the IPv6 address.
			transport := &http.Transport{
				DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					d := &net.Dialer{Timeout: 5 * time.Second}
					return d.DialContext(ctx, "tcp6", fmt.Sprintf("[%s]:%s", addr, port))
				},
			}
			c := &http.Client{
				Transport: transport,
				Timeout:   8 * time.Second,
				CheckRedirect: func(*http.Request, []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			url := fmt.Sprintf("%s://%s/", scheme, asset)
			req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
			if err != nil {
				continue
			}
			resp, err := c.Do(req)
			if err != nil {
				continue
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 512))
			_ = resp.Body.Close()

			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckIPv6ServiceOpen,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityInfo,
				Asset:    asset,
				Title:    fmt.Sprintf("IPv6 %s service accessible on %s [%s]", scheme, asset, addr),
				Description: fmt.Sprintf(
					"The service at %s is accessible via IPv6 address [%s]:%s (status %d). "+
						"Ensure IPv6 endpoints have the same security controls (WAF, firewall rules, "+
						"TLS configuration) as their IPv4 counterparts.",
					asset, addr, port, resp.StatusCode,
				),
				Evidence: map[string]any{
					"ipv6_address": addr,
					"scheme":       scheme,
					"port":         port,
					"status_code":  resp.StatusCode,
				},
				ProofCommand: fmt.Sprintf("curl -6 -sI %s://[%s]/", scheme, addr),
				DiscoveredAt: now,
			})
			break // One scheme is enough to confirm reachability.
		}
	}

	_ = client // suppress unused warning
	return findings, nil
}
