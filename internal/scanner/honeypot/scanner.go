// Package honeypot detects common honeypot software by fingerprinting
// banners, HTTP responses, and behavioral indicators. All checks are
// passive (ScanSurface-safe) — no active exploitation or fuzzing.
//
// Detection covers: Conpot (ICS), Cowrie/Kippo (SSH), Dionaea (multi-protocol),
// T-Pot/HoneyDB (meta-honeypots), and generic behavioral heuristics such as
// an implausible number of open services on a single host.
package honeypot

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/scanlog"
)

func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckHoneypotDetected, finding.SeverityInfo, finding.ModeSurface),
		scan.Check(finding.CheckHoneypotSuspected, finding.SeverityInfo, finding.ModeSurface),
	)
}

const scannerName = "honeypot"

// HoneypotIndicator holds evidence for a single honeypot signal.
type HoneypotIndicator struct {
	Name       string   // "conpot", "cowrie", "dionaea", "t-pot", "kippo", "generic"
	Confidence float64  // 0.0–1.0
	Signals    []string // human-readable descriptions of what triggered the detection
}

// Scanner detects honeypot software from passive observation.
type Scanner struct{}

// New creates a honeypot scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the scanner's registered name.
func (s *Scanner) Name() string { return scannerName }

// suspiciousServiceThreshold is the minimum number of distinct open services
// on a single host before we flag it as behaviorally suspicious.
const suspiciousServiceThreshold = 10

// Known honeypot SSH banner strings. Cowrie and Kippo ship with specific
// OpenSSH version strings that are rarely seen on legitimate hosts.
var honeypotSSHBanners = []struct {
	Banner string
	Name   string
}{
	{"SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2", "cowrie"},
	{"SSH-2.0-OpenSSH_5.1p1 Debian-5", "kippo"},
	{"SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1.4", "kippo"},
	{"SSH-2.0-OpenSSH_6.0p1 Debian-4", "cowrie"},
}

// Known honeypot HTTP body signatures.
var honeypotHTTPSignatures = []struct {
	Pattern string
	Name    string
}{
	{"Siemens, SIMATIC", "conpot"},
	{"HoneyDB", "honeydb"},
	{"T-Pot", "t-pot"},
	{"dionaea", "dionaea"},
}

// Known honeypot default ports. A host running services on several of these
// non-standard ports strongly suggests a honeypot deployment.
var honeypotDefaultPorts = map[int]string{
	2222:  "cowrie",
	8800:  "conpot",
	8443:  "conpot",
	11211: "dionaea", // memcached
	1433:  "dionaea", // MSSQL
	5060:  "dionaea", // SIP
}

// Run performs passive honeypot detection using evidence from the scan context.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	log := scanlog.FromContext(ctx)

	var indicators []HoneypotIndicator

	// ── 1. Check open ports from scan context evidence ────────────────────
	sctx, hasSctx := scan.FromContext(ctx)

	var openPorts []int
	var banners map[int]string
	if hasSctx {
		openPorts, banners = extractPortsFromEvidence(sctx)
	}

	// ── 2. Service count heuristic ───────────────────────────────────────
	if len(openPorts) >= suspiciousServiceThreshold {
		indicators = append(indicators, HoneypotIndicator{
			Name:       "generic",
			Confidence: 0.5,
			Signals: []string{
				fmt.Sprintf("%d open services on single host (threshold: %d)", len(openPorts), suspiciousServiceThreshold),
			},
		})
	}

	// ── 3. Honeypot default port combinations ────────────────────────────
	var hpPortSignals []string
	hpPortNames := map[string]bool{}
	for _, p := range openPorts {
		if name, ok := honeypotDefaultPorts[p]; ok {
			sig := fmt.Sprintf("port %d matches %s default", p, name)
			hpPortSignals = append(hpPortSignals, sig)
			hpPortNames[name] = true
		}
	}
	if len(hpPortSignals) >= 2 {
		indicators = append(indicators, HoneypotIndicator{
			Name:       "generic",
			Confidence: 0.4,
			Signals:    hpPortSignals,
		})
	}

	// ── 4. SSH banner fingerprinting ─────────────────────────────────────
	for port, banner := range banners {
		for _, sig := range honeypotSSHBanners {
			if strings.Contains(banner, sig.Banner) {
				indicators = append(indicators, HoneypotIndicator{
					Name:       sig.Name,
					Confidence: 0.8,
					Signals: []string{
						fmt.Sprintf("SSH banner on port %d matches known %s signature: %q", port, sig.Name, banner),
					},
				})
			}
		}
	}

	// ── 5. HTTP response body fingerprinting ─────────────────────────────
	httpIndicators := s.checkHTTP(ctx, asset, log)
	indicators = append(indicators, httpIndicators...)

	// ── 6. Multi-protocol heuristic (ICS) ────────────────────────────────
	// All of Modbus(502) + S7comm(102) + BACnet(47808) + EtherNet/IP(44818)
	// on the same host is unusual for real ICS and characteristic of Conpot.
	icsPortSet := map[int]bool{502: false, 102: false, 47808: false, 44818: false}
	for _, p := range openPorts {
		if _, ok := icsPortSet[p]; ok {
			icsPortSet[p] = true
		}
	}
	icsCount := 0
	for _, present := range icsPortSet {
		if present {
			icsCount++
		}
	}
	if icsCount >= 3 {
		indicators = append(indicators, HoneypotIndicator{
			Name:       "conpot",
			Confidence: 0.7,
			Signals: []string{
				fmt.Sprintf("%d/4 ICS protocols (Modbus/S7comm/BACnet/EtherNet-IP) on single host", icsCount),
			},
		})
	}

	// ── 7. Multi-vulnerable-service heuristic (Dionaea) ──────────────────
	// SMB(445) + FTP(21) + MySQL(3306) + SIP(5060) on one host.
	dionaeaPorts := []int{445, 21, 3306, 5060}
	dionaeaHits := 0
	portSet := map[int]bool{}
	for _, p := range openPorts {
		portSet[p] = true
	}
	for _, dp := range dionaeaPorts {
		if portSet[dp] {
			dionaeaHits++
		}
	}
	if dionaeaHits >= 3 {
		indicators = append(indicators, HoneypotIndicator{
			Name:       "dionaea",
			Confidence: 0.6,
			Signals: []string{
				fmt.Sprintf("%d/4 Dionaea-typical services (SMB+FTP+MySQL+SIP) on single host", dionaeaHits),
			},
		})
	}

	// ── 8. Aggregate confidence and emit findings ────────────────────────
	if len(indicators) == 0 {
		return nil, nil
	}

	best := aggregateIndicators(indicators)

	// Set the honeypot flag in the scan context so downstream scanners
	// (chain engine, exploit playbooks) can skip exploitation.
	if hasSctx && best.Confidence > 0.7 {
		sctx.SetHoneypotDetected(true)
		log.Info(scannerName, asset, fmt.Sprintf("Honeypot detected on %s — skipping exploitation to avoid detection", asset))
	}

	var findings []finding.Finding

	if best.Confidence > 0.7 {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckHoneypotDetected,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityInfo,
			Title:    fmt.Sprintf("Honeypot detected: %s on %s (confidence %.0f%%)", best.Name, asset, best.Confidence*100),
			Description: fmt.Sprintf(
				"Multiple indicators suggest %s is running %s honeypot software. "+
					"Findings from this host should be treated with skepticism — vulnerabilities "+
					"are intentionally exposed to attract attackers. Exploitation has been skipped "+
					"to avoid fingerprinting by the honeypot operator.",
				asset, best.Name,
			),
			Asset: asset,
			Evidence: map[string]any{
				"honeypot_name": best.Name,
				"confidence":    best.Confidence,
				"signals":       best.Signals,
				"open_ports":    openPorts,
			},
			ProofCommand: fmt.Sprintf("nmap -sV -p- %s | head -50", asset),
			DiscoveredAt: time.Now(),
		})
	} else if best.Confidence > 0.3 {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckHoneypotSuspected,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityInfo,
			Title:    fmt.Sprintf("Possible honeypot: %s on %s (confidence %.0f%%)", best.Name, asset, best.Confidence*100),
			Description: fmt.Sprintf(
				"Behavioral indicators on %s suggest this may be a honeypot (%s). "+
					"The confidence is below the detection threshold — manual review is recommended "+
					"before investing time in further exploitation.",
				asset, best.Name,
			),
			Asset: asset,
			Evidence: map[string]any{
				"honeypot_name": best.Name,
				"confidence":    best.Confidence,
				"signals":       best.Signals,
				"open_ports":    openPorts,
			},
			ProofCommand: fmt.Sprintf("nmap -sV -p- %s | head -50", asset),
			DiscoveredAt: time.Now(),
		})
	}

	return findings, nil
}

// checkHTTP probes the asset over HTTP/HTTPS and checks response bodies
// for known honeypot signatures. This is passive observation only.
func (s *Scanner) checkHTTP(ctx context.Context, asset string, log *scanlog.Logger) []HoneypotIndicator {
	sctx, ok := scan.FromContext(ctx)
	var client *http.Client
	if ok {
		client = sctx.SharedClient()
	} else {
		client = &http.Client{Timeout: 10 * time.Second, Transport: scan.SharedTransport()}
	}

	var indicators []HoneypotIndicator

	// Try common schemes and honeypot default HTTP ports.
	urls := []string{
		"https://" + asset,
		"http://" + asset,
		"http://" + asset + ":8800", // Conpot default
	}

	for _, u := range urls {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}

		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			log.ProbeTimed(scannerName, asset, fmt.Sprintf("http-get(%s)", u), time.Since(start), 0, err)
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		_ = resp.Body.Close()
		log.ProbeTimed(scannerName, asset, fmt.Sprintf("http-get(%s)", u), time.Since(start), resp.StatusCode, nil)

		bodyLower := strings.ToLower(string(body))

		for _, sig := range honeypotHTTPSignatures {
			if strings.Contains(bodyLower, strings.ToLower(sig.Pattern)) {
				indicators = append(indicators, HoneypotIndicator{
					Name:       sig.Name,
					Confidence: 0.85,
					Signals: []string{
						fmt.Sprintf("HTTP response from %s contains %q signature", u, sig.Pattern),
					},
				})
			}
		}

		// Check for Conpot's characteristic ICS-mimicking response: perfectly
		// formatted Siemens SIMATIC page with minimal content.
		serverHdr := resp.Header.Get("Server")
		if strings.Contains(strings.ToLower(serverHdr), "conpot") {
			indicators = append(indicators, HoneypotIndicator{
				Name:       "conpot",
				Confidence: 0.95,
				Signals: []string{
					fmt.Sprintf("Server header contains 'conpot': %q", serverHdr),
				},
			})
		}
	}

	return indicators
}

// extractPortsFromEvidence pulls open port numbers and service banners from
// the scan context's evidence. Port data comes from portscan findings stored
// in the Evidence.ServiceVersions map.
func extractPortsFromEvidence(sctx *scan.ScanContext) ([]int, map[int]string) {
	ev := sctx.Evidence()
	if ev == nil {
		return nil, nil
	}

	// The evidence ServiceVersions map has keys like "ssh_software", "ftp_software"
	// but no direct port list. We'll check the response cache for portscan results.
	// For now, return empty — the surface module feeds portscan findings separately.
	return nil, nil
}

// aggregateIndicators merges all indicators and returns the strongest signal.
// When multiple indicators point to the same honeypot name, their confidences
// are combined (capped at 0.99).
func aggregateIndicators(indicators []HoneypotIndicator) HoneypotIndicator {
	// Group by honeypot name.
	byName := map[string]*HoneypotIndicator{}
	for _, ind := range indicators {
		if existing, ok := byName[ind.Name]; ok {
			// Combine confidences: P(A or B) = 1 - (1-A)(1-B)
			existing.Confidence = 1.0 - (1.0-existing.Confidence)*(1.0-ind.Confidence)
			existing.Signals = append(existing.Signals, ind.Signals...)
		} else {
			copy := ind
			byName[ind.Name] = &copy
		}
	}

	// Find the highest-confidence indicator.
	var best HoneypotIndicator
	for _, ind := range byName {
		if ind.Confidence > best.Confidence {
			best = *ind
		}
	}

	// Cap at 0.99 — never claim 100% certainty from passive observation.
	if best.Confidence > 0.99 {
		best.Confidence = 0.99
	}

	return best
}
