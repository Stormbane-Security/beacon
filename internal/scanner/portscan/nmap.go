package portscan

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

// nmapRun wraps the output of nmap -oX (XML output).
type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Ports []nmapPort `xml:"ports>port"`
	OS    nmapOS     `xml:"os"`
}

type nmapOS struct {
	OSMatches []nmapOSMatch `xml:"osmatch"`
}

type nmapOSMatch struct {
	Name     string       `xml:"name,attr"`
	Accuracy string       `xml:"accuracy,attr"`
	OSClass  []nmapOSClass `xml:"osclass"`
}

type nmapOSClass struct {
	Type   string `xml:"type,attr"`
	Vendor string `xml:"vendor,attr"`
	OSFam  string `xml:"osfamily,attr"`
	OSGen  string `xml:"osgen,attr"`
	CPE    string `xml:"cpe"`
}

type nmapPort struct {
	Protocol string       `xml:"protocol,attr"`
	PortID   int          `xml:"portid,attr"`
	State    nmapState    `xml:"state"`
	Service  nmapService  `xml:"service"`
	Scripts  []nmapScript `xml:"script"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
}

type nmapScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

// runNmap executes nmap against the asset on the given open ports and returns
// additional findings from service version detection and NSE scripts.
// Returns nil (empty) when nmapBin is "" or nmap fails — the pure-Go scan
// findings are always emitted regardless.
//
// Surface mode: service version detection + SSH/DNS/FTP/SNMP scripts
// Deep mode: adds --script vuln for CVE/exploitation templates, OS detection,
// and a separate UDP scan for SNMP on port 161.
func (s *Scanner) runNmap(ctx context.Context, asset string, openPorts map[int]string, scanType module.ScanType) []finding.Finding {
	if s.nmapBin == "" {
		return nil
	}
	if len(openPorts) == 0 {
		return nil
	}

	// Build comma-separated port list
	portList := portMapToList(openPorts)

	// Build nmap args. Always use -oX - (XML to stdout) so we can parse.
	// -Pn: skip host discovery (we already know the host is up).
	// -sV: service version detection.
	// --version-intensity 2: light fingerprinting — fast, low noise.
	// -T3: polite timing — avoids triggering IDS rate-limit rules.
	args := []string{
		"-oX", "-",
		"-Pn",
		"-sV", "--version-intensity", "2",
		"-T3",
		"-p", portList,
	}

	// Surface mode: add targeted NSE scripts for common misconfigs.
	// Scripts used are information-gathering only (no exploitation).
	surfaceScripts := []string{
		"ssh-auth-methods",
		"ssh2-enum-algos",
		"dns-recursion",
		"ftp-anon",
		"snmp-info",
		"banner",
	}
	args = append(args, "--script", strings.Join(surfaceScripts, ","))

	// Deep mode: add NSE vulnerability scripts and OS detection.
	// These probe for specific CVEs — only allowed with explicit permission.
	if scanType == module.ScanDeep {
		vulnScripts := []string{
			"vuln",
			"ms17-010",
			"ssl-heartbleed",
			"ssl-drown",
			"ssl-poodle",
			"smb-vuln-ms17-010",
			"smb-vuln-ms08-067", // CVE-2008-4250 Windows Server Service RCE (Conficker)
			"http-shellshock",
		}
		args = append(args, "--script", strings.Join(vulnScripts, ","))

		// OS detection: requires raw-socket capability (root/CAP_NET_RAW).
		// We add -O and tolerate failure gracefully — if nmap lacks privilege
		// it will exit non-zero and we simply return no OS finding.
		args = append(args, "-O")
	}

	args = append(args, asset)

	// 5 minutes max — nmap with vuln scripts can be slow on many ports
	nmapCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(nmapCtx, s.nmapBin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	proofCmd := buildProofCommand(s.nmapBin, args, asset)

	var findings []finding.Finding

	if err := cmd.Run(); err != nil {
		// nmap exiting non-zero is common (host down, OS detection without root,
		// etc.) — not a fatal error. Still attempt to parse whatever XML came out.
		if stdout.Len() == 0 {
			return nil
		}
	}

	findings = append(findings, parseNmapXML(asset, stdout.Bytes(), scanType, proofCmd)...)

	// Deep mode: run a separate UDP scan for SNMP on port 161.
	// UDP requires -sU which in turn requires root/CAP_NET_RAW; tolerate
	// permission errors gracefully.
	if scanType == module.ScanDeep {
		if _, hasSNMP := openPorts[161]; hasSNMP {
			udpArgs := []string{
				"-oX", "-",
				"-Pn",
				"-sU",
				"-p", "161",
				"--script", "snmp-info",
				"-T3",
				asset,
			}
			udpProofCmd := buildProofCommand(s.nmapBin, udpArgs, asset)
			udpCtx, udpCancel := context.WithTimeout(ctx, 2*time.Minute)
			defer udpCancel()

			udpCmd := exec.CommandContext(udpCtx, s.nmapBin, udpArgs...)
			var udpStdout bytes.Buffer
			udpCmd.Stdout = &udpStdout

			if err := udpCmd.Run(); err == nil || udpStdout.Len() > 0 {
				findings = append(findings, parseNmapXML(asset, udpStdout.Bytes(), scanType, udpProofCmd)...)
			}
		}
	}

	return findings
}

// buildProofCommand assembles the nmap command string suitable for the
// ProofCommand field (the full command a user could paste into a terminal).
func buildProofCommand(bin string, args []string, _ string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, bin)
	for _, a := range args {
		if strings.ContainsAny(a, " \t\n") {
			parts = append(parts, "'"+a+"'")
		} else {
			parts = append(parts, a)
		}
	}
	return strings.Join(parts, " ")
}

// parseNmapXML parses nmap XML output and emits findings.
func parseNmapXML(asset string, data []byte, scanType module.ScanType, proofCmd string) []finding.Finding {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil
	}

	var findings []finding.Finding
	now := time.Now()

	for _, host := range run.Hosts {
		// OS detection finding (deep mode only, populated when -O was used)
		if scanType == module.ScanDeep {
			if osF := buildOSFinding(asset, host.OS, proofCmd, now); osF != nil {
				findings = append(findings, *osF)
			}
		}

		for _, port := range host.Ports {
			if port.State.State != "open" {
				continue
			}

			// Service version finding
			if port.Service.Product != "" || port.Service.Version != "" {
				version := strings.TrimSpace(port.Service.Product + " " + port.Service.Version)
				findings = append(findings, finding.Finding{
					CheckID:      finding.CheckNmapServiceVersion,
					Module:       "surface",
					Scanner:      scannerName,
					Severity:     finding.SeverityInfo,
					Asset:        asset,
					Title:        fmt.Sprintf("Service version: port %d/%s = %s", port.PortID, port.Protocol, version),
					Description:  fmt.Sprintf("nmap identified %s running on port %d (%s/%s).", version, port.PortID, port.Service.Name, port.Protocol),
					Evidence: map[string]any{
						"port":     port.PortID,
						"protocol": port.Protocol,
						"product":  port.Service.Product,
						"version":  port.Service.Version,
						"extra":    port.Service.ExtraInfo,
					},
					ProofCommand: proofCmd,
					DiscoveredAt: now,
				})
			}

			// Process NSE script output
			for _, script := range port.Scripts {
				fs := interpretNmapScript(asset, port.PortID, script, proofCmd, now)
				findings = append(findings, fs...)
			}
		}
	}

	return findings
}

// buildOSFinding constructs a CheckNmapOSDetected finding from the parsed OS
// data, or returns nil when no OS match was found.
func buildOSFinding(asset string, os nmapOS, proofCmd string, now time.Time) *finding.Finding {
	if len(os.OSMatches) == 0 {
		return nil
	}

	best := os.OSMatches[0]
	if best.Name == "" {
		return nil
	}

	// Collect CPEs from the best OS match
	var cpes []string
	for _, cls := range best.OSClass {
		if cls.CPE != "" {
			cpes = append(cpes, cls.CPE)
		}
	}

	ev := map[string]any{
		"os_name":     best.Name,
		"os_accuracy": best.Accuracy,
	}
	if len(cpes) > 0 {
		ev["cpe"] = cpes
	}

	f := &finding.Finding{
		CheckID:      finding.CheckNmapOSDetected,
		Module:       "surface",
		Scanner:      scannerName,
		Severity:     finding.SeverityInfo,
		Asset:        asset,
		Title:        fmt.Sprintf("OS detected: %s", best.Name),
		Description:  fmt.Sprintf("nmap OS detection identified the remote host as '%s' (accuracy: %s%%). OS fingerprinting results should be treated as informational.", best.Name, best.Accuracy),
		Evidence:     ev,
		ProofCommand: proofCmd,
		DeepOnly:     true,
		DiscoveredAt: now,
	}
	return f
}

// interpretNmapScript converts a single NSE script result into findings.
func interpretNmapScript(asset string, port int, script nmapScript, proofCmd string, now time.Time) []finding.Finding {
	output := strings.TrimSpace(script.Output)
	if output == "" {
		return nil
	}
	lower := strings.ToLower(output)

	switch script.ID {
	case "ftp-anon":
		if strings.Contains(lower, "anonymous ftp login allowed") {
			return []finding.Finding{{
				CheckID:      finding.CheckNmapFTPAnonymous,
				Module:       "surface",
				Scanner:      scannerName,
				Severity:     finding.SeverityHigh,
				Asset:        asset,
				Title:        fmt.Sprintf("Anonymous FTP login allowed on port %d", port),
				Description:  "The FTP server accepts anonymous logins. Anyone can list and potentially download files without credentials.",
				Evidence:     map[string]any{"port": port, "script": script.ID, "output": truncate(output, 200)},
				ProofCommand: proofCmd,
				DiscoveredAt: now,
			}}
		}

	case "dns-recursion":
		// nmap dns-recursion script outputs "RECURSION" in its output when
		// recursion is enabled. Also handle older wording variants.
		if strings.Contains(lower, "recursion") {
			return []finding.Finding{{
				CheckID:      finding.CheckNmapDNSRecursion,
				Module:       "surface",
				Scanner:      scannerName,
				Severity:     finding.SeverityHigh,
				Asset:        asset,
				Title:        fmt.Sprintf("Open DNS recursive resolver on port %d", port),
				Description:  "This DNS server answers recursive queries from external hosts. Open resolvers can be abused for DNS amplification DDoS attacks.",
				Evidence:     map[string]any{"port": port, "script": script.ID, "output": truncate(output, 200)},
				ProofCommand: proofCmd,
				DiscoveredAt: now,
			}}
		}

	case "snmp-info":
		// Any successful SNMP info dump means community string is default/guessable
		if strings.Contains(lower, "sysname") || strings.Contains(lower, "sysdescr") {
			return []finding.Finding{{
				CheckID:      finding.CheckNmapSNMPExposed,
				Module:       "surface",
				Scanner:      scannerName,
				Severity:     finding.SeverityHigh,
				Asset:        asset,
				Title:        fmt.Sprintf("SNMP community string accepted on port %d", port),
				Description:  "The SNMP service responded to a community string probe, exposing system information. Default community strings ('public'/'private') allow reading system config and network topology.",
				Evidence:     map[string]any{"port": port, "script": script.ID, "output": truncate(output, 300)},
				ProofCommand: proofCmd,
				DiscoveredAt: now,
			}}
		}

	case "ssh2-enum-algos":
		weakAlgs := []string{"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "arcfour", "des-cbc", "3des-cbc", "blowfish-cbc", "cast128-cbc", "hmac-md5", "hmac-sha1"}
		var found []string
		for _, alg := range weakAlgs {
			if strings.Contains(lower, alg) {
				found = append(found, alg)
			}
		}
		if len(found) > 0 {
			return []finding.Finding{{
				CheckID:      finding.CheckNmapSSHAlgorithms,
				Module:       "surface",
				Scanner:      scannerName,
				Severity:     finding.SeverityHigh,
				Asset:        asset,
				Title:        fmt.Sprintf("SSH weak algorithms on port %d: %s", port, strings.Join(found, ", ")),
				Description:  "The SSH server supports deprecated or weak cryptographic algorithms that are vulnerable to downgrade attacks.",
				Evidence:     map[string]any{"port": port, "weak_algs": found, "output": truncate(output, 300)},
				ProofCommand: proofCmd,
				DiscoveredAt: now,
			}}
		}

	case "ssl-heartbleed":
		if strings.Contains(lower, "vulnerable") {
			return []finding.Finding{{
				CheckID:      finding.CheckNmapVulnScript,
				Module:       "surface",
				Scanner:      scannerName,
				Severity:     finding.SeverityCritical,
				Asset:        asset,
				Title:        fmt.Sprintf("Heartbleed (CVE-2014-0160) detected on port %d", port),
				Description:  "The server is vulnerable to the Heartbleed OpenSSL bug. An attacker can read 64KB of server memory per request, potentially leaking private keys, session tokens, and credentials.",
				Evidence:     map[string]any{"port": port, "cve": "CVE-2014-0160", "script": script.ID, "output": truncate(output, 200)},
				ProofCommand: proofCmd,
				DiscoveredAt: now,
			}}
		}

	case "ms17-010", "smb-vuln-ms17-010":
		if strings.Contains(lower, "vulnerable") {
			return []finding.Finding{{
				CheckID:      finding.CheckNmapVulnScript,
				Module:       "surface",
				Scanner:      scannerName,
				Severity:     finding.SeverityCritical,
				Asset:        asset,
				Title:        fmt.Sprintf("EternalBlue (MS17-010 / CVE-2017-0144) detected on port %d", port),
				Description:  "The SMB service is vulnerable to EternalBlue (MS17-010), used by WannaCry and NotPetya. Remote code execution without credentials is possible.",
				Evidence:     map[string]any{"port": port, "cve": "CVE-2017-0144", "script": script.ID, "output": truncate(output, 200)},
				ProofCommand: proofCmd,
				DiscoveredAt: now,
			}}
		}

	case "smb-vuln-ms08-067":
		if strings.Contains(lower, "vulnerable") {
			return []finding.Finding{{
				CheckID:      finding.CheckNmapVulnScript,
				Module:       "surface",
				Scanner:      scannerName,
				Severity:     finding.SeverityCritical,
				Asset:        asset,
				Title:        fmt.Sprintf("MS08-067 (CVE-2008-4250) detected on port %d", port),
				Description:  "The SMB service is vulnerable to MS08-067 (Conficker worm, CVSS 10.0). This Windows Server Service flaw allows unauthenticated remote code execution and was exploited at massive scale by Conficker/Downadup. Patch immediately via KB958644.",
				Evidence:     map[string]any{"port": port, "cve": "CVE-2008-4250", "script": script.ID, "output": truncate(output, 200)},
				ProofCommand: proofCmd,
				DiscoveredAt: now,
			}}
		}

	case "http-shellshock":
		if strings.Contains(lower, "vulnerable") {
			return []finding.Finding{{
				CheckID:      finding.CheckNmapVulnScript,
				Module:       "surface",
				Scanner:      scannerName,
				Severity:     finding.SeverityCritical,
				Asset:        asset,
				Title:        fmt.Sprintf("Shellshock (CVE-2014-6271) detected on port %d", port),
				Description:  "The web server is vulnerable to Shellshock, a bash CGI injection vulnerability that allows remote command execution via HTTP headers.",
				Evidence:     map[string]any{"port": port, "cve": "CVE-2014-6271", "script": script.ID, "output": truncate(output, 200)},
				ProofCommand: proofCmd,
				DiscoveredAt: now,
			}}
		}

	default:
		// For generic vuln script hits, emit a high-severity finding with the raw output
		if strings.Contains(lower, "vulnerable") && !strings.Contains(lower, "not vulnerable") {
			return []finding.Finding{{
				CheckID:      finding.CheckNmapVulnScript,
				Module:       "surface",
				Scanner:      scannerName,
				Severity:     finding.SeverityHigh,
				Asset:        asset,
				Title:        fmt.Sprintf("NSE vulnerability script hit: %s on port %d", script.ID, port),
				Description:  fmt.Sprintf("nmap NSE script '%s' reported a potential vulnerability on port %d. Review the output for details.", script.ID, port),
				Evidence:     map[string]any{"port": port, "script": script.ID, "output": truncate(output, 400)},
				ProofCommand: proofCmd,
				DiscoveredAt: now,
			}}
		}
	}

	return nil
}

// portMapToList converts a port→service map to a comma-separated port string for nmap -p.
func portMapToList(ports map[int]string) string {
	list := make([]string, 0, len(ports))
	for p := range ports {
		list = append(list, fmt.Sprintf("%d", p))
	}
	return strings.Join(list, ",")
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
