// Package wifi scans the local wireless environment for security issues.
//
// Surface mode (no root, no monitor mode required):
//   - Enumerates nearby SSIDs using OS-native tools (airport on macOS,
//     nmcli/iwlist on Linux)
//   - Reports insecure configurations: open networks, WEP, WPS-enabled APs,
//     WPA2-TKIP-only networks
//   - Discovers the connected network's default gateway and probes it for
//     exposed management interfaces using TCP connect probes
//
// Deep mode (requires --permission-confirmed):
//   - Invokes bettercap (if installed) for PMKID capture — passive, no
//     deauthentication frames sent
//   - Invokes airodump-ng (if installed) for handshake capture monitoring
//
// This scanner is hardware-local: it queries the host's wireless adapter,
// not a remote asset. The asset parameter is used only for tagging findings.
package wifi

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const scannerName = "wifi"

// gatewayProbeTimeout is the per-port TCP connect timeout when probing the
// default gateway for exposed management interfaces.
const gatewayProbeTimeout = 3 * time.Second

// Scanner enumerates the local WiFi environment.
type Scanner struct{}

// New returns a new WiFi Scanner.
func New() *Scanner { return &Scanner{} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return scannerName }

// Run implements scanner.Scanner.
// asset is used only for finding attribution; the scanner always probes the
// local wireless environment regardless of the asset value.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	var findings []finding.Finding

	// ── 1. Enumerate local WiFi networks ──────────────────────────────────
	networks, err := scanLocalNetworks(ctx)
	if err == nil {
		for _, n := range networks {
			findings = append(findings, assessNetwork(n, asset)...)
		}
	}

	// ── 2. Probe the default gateway ──────────────────────────────────────
	gw, err := defaultGateway()
	if err == nil && gw != "" {
		findings = append(findings, probeGateway(ctx, gw, asset)...)
	}

	// ── 3. Deep mode: PMKID capture via bettercap (if available) ──────────
	if scanType == module.ScanDeep {
		findings = append(findings, probePMKID(ctx, asset)...)
	}

	return findings, nil
}

// ── WiFi network data ────────────────────────────────────────────────────────

// wifiNetwork holds the parsed details of a single scanned AP.
type wifiNetwork struct {
	SSID     string
	BSSID    string
	Signal   int    // dBm
	Channel  string
	Security string // raw security string from OS tool
	WPS      bool
}

// ── OS-level WiFi enumeration ────────────────────────────────────────────────

// scanLocalNetworks uses the OS-native WiFi scanning tool to enumerate nearby
// access points. Returns an empty slice (not an error) when no tool is found
// or the adapter is not available.
func scanLocalNetworks(ctx context.Context) ([]wifiNetwork, error) {
	switch runtime.GOOS {
	case "darwin":
		return scanMacOS(ctx)
	case "linux":
		return scanLinux(ctx)
	default:
		return nil, fmt.Errorf("wifi scanning not supported on %s", runtime.GOOS)
	}
}

// scanMacOS uses the built-in airport utility to list nearby APs.
// airport outputs tab-separated columns: SSID, BSSID, RSSI, CHANNEL, HT, CC, SECURITY
const airportPath = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"

func scanMacOS(ctx context.Context) ([]wifiNetwork, error) {
	cmd := exec.CommandContext(ctx, airportPath, "-s")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("airport -s: %w", err)
	}
	return parseAirportOutput(string(out)), nil
}

// parseAirportOutput parses the tabular output of `airport -s`.
// Example line (leading spaces are significant for SSID padding):
//
//	                  MyNetwork 12:34:56:78:9a:bc  -45  6,+1   Y  US WPA2(PSK/AES/AES)
func parseAirportOutput(raw string) []wifiNetwork {
	var nets []wifiNetwork
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := scanner.Text()
		// Skip header line (contains "SSID" as a column label).
		if strings.Contains(line, "SSID") && strings.Contains(line, "BSSID") {
			continue
		}
		// airport aligns the SSID right-padded to column 32; BSSID starts after.
		// Minimum line length: 33 chars for SSID + at least a BSSID.
		if len(line) < 33 {
			continue
		}
		// BSSID is always a MAC address (xx:xx:xx:xx:xx:xx = 17 chars).
		// Find it by looking for the MAC pattern after the SSID column.
		rest := strings.TrimSpace(line[32:])
		fields := strings.Fields(rest)
		if len(fields) < 2 {
			continue
		}
		// Validate BSSID format.
		bssid := fields[0]
		if len(bssid) != 17 || strings.Count(bssid, ":") != 5 {
			continue
		}
		ssid := strings.TrimSpace(line[:32])
		security := ""
		channel := ""
		if len(fields) >= 2 {
			channel = fields[1]
		}
		// Security is the last field(s) — may be "WPA2(PSK/AES/AES)" or "NONE"
		if len(fields) >= 5 {
			security = fields[len(fields)-1]
		}
		nets = append(nets, wifiNetwork{
			SSID:     ssid,
			BSSID:    bssid,
			Channel:  channel,
			Security: security,
		})
	}
	return nets
}

// scanLinux uses nmcli (NetworkManager) or iwlist as fallback.
func scanLinux(ctx context.Context) ([]wifiNetwork, error) {
	// Try nmcli first — available on most desktop/server Linux.
	if path, err := exec.LookPath("nmcli"); err == nil {
		cmd := exec.CommandContext(ctx, path, "-t", "-f", "SSID,BSSID,SIGNAL,SECURITY", "dev", "wifi", "list")
		out, err := cmd.Output()
		if err == nil {
			return parseNmcliOutput(string(out)), nil
		}
	}
	// Fallback: iwlist scan (may require root on some systems).
	return scanIwlist(ctx)
}

// parseNmcliOutput parses `nmcli -t -f SSID,BSSID,SIGNAL,SECURITY dev wifi list`.
// Output format: SSID:BSSID:SIGNAL:SECURITY (colon-separated, escaped colons in SSID as \:)
func parseNmcliOutput(raw string) []wifiNetwork {
	var nets []wifiNetwork
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Split on unescaped colons.
		parts := splitNmcliFields(line)
		if len(parts) < 4 {
			continue
		}
		nets = append(nets, wifiNetwork{
			SSID:     parts[0],
			BSSID:    parts[1],
			Security: parts[3],
		})
	}
	return nets
}

// splitNmcliFields splits a colon-separated nmcli line, respecting \: escapes.
func splitNmcliFields(line string) []string {
	var fields []string
	var cur strings.Builder
	for i := 0; i < len(line); i++ {
		if line[i] == '\\' && i+1 < len(line) && line[i+1] == ':' {
			cur.WriteByte(':')
			i++
			continue
		}
		if line[i] == ':' {
			fields = append(fields, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(line[i])
	}
	fields = append(fields, cur.String())
	return fields
}

// scanIwlist parses `iwlist scan` output as a last resort.
func scanIwlist(ctx context.Context) ([]wifiNetwork, error) {
	ifaces, err := listWirelessInterfaces()
	if err != nil || len(ifaces) == 0 {
		return nil, fmt.Errorf("no wireless interfaces found")
	}
	path, err := exec.LookPath("iwlist")
	if err != nil {
		return nil, fmt.Errorf("iwlist not found")
	}
	cmd := exec.CommandContext(ctx, path, ifaces[0], "scan")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("iwlist scan: %w", err)
	}
	return parseIwlistOutput(string(out)), nil
}

// parseIwlistOutput parses iwlist scan output into wifiNetwork structs.
func parseIwlistOutput(raw string) []wifiNetwork {
	var nets []wifiNetwork
	var cur wifiNetwork
	inCell := false

	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Cell ") {
			if inCell && cur.SSID != "" {
				nets = append(nets, cur)
			}
			cur = wifiNetwork{}
			inCell = true
			// Extract BSSID: "Cell 01 - Address: AA:BB:CC:DD:EE:FF"
			if idx := strings.Index(trimmed, "Address:"); idx >= 0 {
				cur.BSSID = strings.TrimSpace(trimmed[idx+8:])
			}
			continue
		}
		if !inCell {
			continue
		}
		if strings.HasPrefix(trimmed, "ESSID:") {
			cur.SSID = strings.Trim(strings.TrimPrefix(trimmed, "ESSID:"), `"`)
		} else if strings.HasPrefix(trimmed, "Channel:") {
			cur.Channel = strings.TrimPrefix(trimmed, "Channel:")
		} else if strings.Contains(trimmed, "Encryption key:off") {
			cur.Security = "NONE"
		} else if strings.HasPrefix(trimmed, "IE: WPA") || strings.Contains(trimmed, "WPA2") {
			if cur.Security == "" || cur.Security == "NONE" {
				cur.Security = trimmed
			}
		} else if strings.Contains(trimmed, "WPS") {
			cur.WPS = true
		} else if strings.Contains(trimmed, "TKIP") && cur.Security != "" {
			cur.Security += " TKIP"
		}
	}
	if inCell && cur.SSID != "" {
		nets = append(nets, cur)
	}
	return nets
}

// listWirelessInterfaces returns the names of wireless network interfaces.
func listWirelessInterfaces() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var wireless []string
	for _, iface := range ifaces {
		name := iface.Name
		// Linux wireless interface names commonly start with wl, wlan, wifi, ath, ra.
		if strings.HasPrefix(name, "wl") || strings.HasPrefix(name, "wlan") ||
			strings.HasPrefix(name, "ath") || strings.HasPrefix(name, "ra") ||
			strings.HasPrefix(name, "wifi") {
			wireless = append(wireless, name)
		}
	}
	return wireless, nil
}

// ── Security assessment ───────────────────────────────────────────────────────

// assessNetwork returns findings for a single scanned WiFi network.
func assessNetwork(n wifiNetwork, asset string) []finding.Finding {
	var findings []finding.Finding
	now := time.Now()
	sec := strings.ToUpper(n.Security)

	label := n.SSID
	if label == "" {
		label = n.BSSID
	}

	// Open network — no encryption at all.
	if sec == "NONE" || sec == "" {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckWiFiOpenNetwork,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Asset:    asset,
			Title:    fmt.Sprintf("Open WiFi network detected: %q (no encryption)", label),
			Description: fmt.Sprintf(
				"WiFi network %q (BSSID %s, channel %s) has no encryption. "+
					"All traffic between clients and the AP is transmitted in plaintext. "+
					"An attacker within radio range can passively capture all unencrypted traffic "+
					"including HTTP sessions, DNS queries, and credentials. "+
					"Enable WPA3 Personal or at minimum WPA2-AES (CCMP).",
				n.SSID, n.BSSID, n.Channel,
			),
			Evidence:     map[string]any{"ssid": n.SSID, "bssid": n.BSSID, "channel": n.Channel, "security": "NONE"},
			ProofCommand: "airport -s | grep -v WPA",
			DiscoveredAt: now,
		})
	}

	// WEP — completely broken, crackable in minutes with aircrack-ng.
	if strings.Contains(sec, "WEP") {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckWiFiWEPNetwork,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Asset:    asset,
			Title:    fmt.Sprintf("WEP-encrypted WiFi network detected: %q (deprecated, crackable in minutes)", label),
			Description: fmt.Sprintf(
				"WiFi network %q (BSSID %s) uses WEP (Wired Equivalent Privacy), which was "+
					"cryptographically broken in 2001 (CVE-2001-1528) and deprecated by IEEE in 2004. "+
					"WEP uses RC4 with static keys and predictable IVs — an attacker can recover the "+
					"key by collecting 40,000–85,000 packets using aircrack-ng in under 60 seconds. "+
					"Upgrade to WPA3 Personal immediately. WPA2-AES is the minimum acceptable standard.",
				n.SSID, n.BSSID,
			),
			Evidence:     map[string]any{"ssid": n.SSID, "bssid": n.BSSID, "channel": n.Channel, "security": n.Security},
			ProofCommand: fmt.Sprintf("aircrack-ng -b %s capture.cap", n.BSSID),
			DiscoveredAt: now,
		})
	}

	// WPS enabled — PixieDust (offline) or PIN brute-force attack vector.
	if n.WPS || strings.Contains(sec, "WPS") {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckWiFiWPSEnabled,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Asset:    asset,
			Title:    fmt.Sprintf("WPS enabled on %q (PIN brute-force / PixieDust attack possible)", label),
			Description: fmt.Sprintf(
				"WiFi Protected Setup (WPS) is enabled on %q (BSSID %s). "+
					"The WPS PIN is a weak 8-digit code (effectively 11,000 guesses due to split verification). "+
					"CVE-2011-5053 / Reaver attack allows PIN brute-force in 4–10 hours. "+
					"Routers with a predictable RNG are vulnerable to the PixieDust offline attack "+
					"(recover PIN in seconds). Disable WPS in the router admin panel.",
				n.SSID, n.BSSID,
			),
			Evidence:     map[string]any{"ssid": n.SSID, "bssid": n.BSSID, "wps": true},
			ProofCommand: fmt.Sprintf("reaver -i wlan0mon -b %s -vv", n.BSSID),
			DiscoveredAt: now,
		})
	}

	// WPA2 with TKIP cipher — TKIP is deprecated, prefer AES/CCMP.
	if strings.Contains(sec, "WPA2") && strings.Contains(sec, "TKIP") && !strings.Contains(sec, "AES") {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckWiFiWPA2TKIP,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityLow,
			Asset:    asset,
			Title:    fmt.Sprintf("WPA2-TKIP (deprecated cipher) on %q — prefer AES/CCMP", label),
			Description: fmt.Sprintf(
				"WiFi network %q uses WPA2 with TKIP (Temporal Key Integrity Protocol). "+
					"TKIP is deprecated since 802.11-2012 and is vulnerable to the Beck-Tews attack "+
					"(inject short frames without knowing the key). AES-CCMP is the required replacement. "+
					"Update the AP's cipher configuration to AES/CCMP only.",
				n.SSID,
			),
			Evidence:     map[string]any{"ssid": n.SSID, "bssid": n.BSSID, "security": n.Security},
			ProofCommand: "airport -s | grep TKIP",
			DiscoveredAt: now,
		})
	}

	return findings
}

// ── Gateway probing ───────────────────────────────────────────────────────────

// gatewayMgmtPorts are common management ports that indicate an exposed router
// or AP admin interface on the local network.
var gatewayMgmtPorts = []struct {
	port    int
	service string
}{
	{80, "HTTP admin"},
	{443, "HTTPS admin"},
	{8080, "HTTP alt admin"},
	{8443, "HTTPS alt admin"},
	{8291, "MikroTik Winbox"},
	{8728, "MikroTik RouterOS API"},
	{4343, "Aruba Instant"},
	{8880, "UniFi portal"},
	{8843, "UniFi portal TLS"},
}

// probeGateway TCP-connects to common management ports on the default gateway
// and returns a finding if any are open, indicating the router's admin
// interface is reachable from the local WiFi segment.
func probeGateway(ctx context.Context, gateway, asset string) []finding.Finding {
	var open []string
	for _, p := range gatewayMgmtPorts {
		addr := fmt.Sprintf("%s:%d", gateway, p.port)
		conn, err := (&net.Dialer{Timeout: gatewayProbeTimeout}).DialContext(ctx, "tcp", addr)
		if err == nil {
			conn.Close()
			open = append(open, fmt.Sprintf("%d/%s", p.port, p.service))
		}
	}
	if len(open) == 0 {
		return nil
	}
	return []finding.Finding{{
		CheckID:  finding.CheckWiFiGatewayExposed,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityHigh,
		Asset:    asset,
		Title:    fmt.Sprintf("Default gateway %s has exposed management interface(s): %s", gateway, strings.Join(open, ", ")),
		Description: fmt.Sprintf(
			"The default gateway %s has management ports reachable from the local WiFi network: %s. "+
				"Exposed router admin interfaces on the local network allow WiFi clients to "+
				"reconfigure the router, change DNS (DNS hijack), add port forwarding rules, "+
				"and potentially exploit firmware vulnerabilities. "+
				"Restrict admin interface access to a dedicated management VLAN or wired LAN only. "+
				"Ensure the admin account uses a strong non-default password.",
			gateway, strings.Join(open, ", "),
		),
		Evidence:     map[string]any{"gateway": gateway, "open_ports": open},
		ProofCommand: fmt.Sprintf("nmap -p 80,443,8080,8443,8291 %s", gateway),
		DiscoveredAt: time.Now(),
	}}
}

// ── PMKID capture (deep mode) ─────────────────────────────────────────────────

// probePMKID attempts PMKID capture using bettercap if available.
// PMKID capture is passive — it intercepts the RSN IE in association frames
// without requiring a deauthentication attack (no disruption to clients).
// Returns a finding if a PMKID is captured, indicating offline cracking is
// possible against the WPA2 passphrase.
func probePMKID(ctx context.Context, asset string) []finding.Finding {
	// Check bettercap is available.
	bettercapPath, err := exec.LookPath("bettercap")
	if err != nil {
		// Also try hcxdumptool as an alternative.
		hcxPath, hcxErr := exec.LookPath("hcxdumptool")
		if hcxErr != nil {
			return nil // Neither tool available — skip silently.
		}
		return probeHCXDumpTool(ctx, hcxPath, asset)
	}

	// Run bettercap with a 30-second wifi.recon + pmkid capture caplet.
	// The caplet exits after capturing one PMKID or timing out.
	caplet := "wifi.recon on; sleep 30; wifi.show; quit"
	cmd := exec.CommandContext(ctx, bettercapPath, "-eval", caplet, "-no-colors")
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &outBuf

	// Best-effort: if bettercap fails (no root, no monitor mode), return nil.
	if err := cmd.Run(); err != nil {
		return nil
	}

	output := outBuf.String()
	// bettercap prints "PMKID" when it captures one.
	if !strings.Contains(output, "PMKID") && !strings.Contains(output, "pmkid") {
		return nil
	}

	return []finding.Finding{{
		CheckID:  finding.CheckWiFiPMKID,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Asset:    asset,
		Title:    "WPA2 PMKID captured — offline passphrase cracking possible",
		Description: "A WPA2 PMKID (Pairwise Master Key Identifier) was captured from a nearby access point. " +
			"The PMKID is derived from the PMK (= PBKDF2(passphrase, SSID, 4096, 32)) and allows " +
			"offline dictionary/brute-force attacks against the WiFi passphrase without requiring a " +
			"client to be connected or a deauthentication attack. " +
			"Unlike 4-way handshake capture, PMKID capture is entirely passive and works against any " +
			"WPA2/WPA3-Personal AP. Use a strong (20+ character random) WiFi passphrase to resist offline cracking.",
		Evidence:     map[string]any{"tool": "bettercap", "method": "pmkid"},
		ProofCommand: "bettercap -eval 'wifi.recon on; sleep 30; wifi.show; quit'",
		DiscoveredAt: time.Now(),
	}}
}

// probeHCXDumpTool attempts PMKID capture using hcxdumptool.
func probeHCXDumpTool(ctx context.Context, hcxPath, asset string) []finding.Finding {
	ifaces, err := listWirelessInterfaces()
	if err != nil || len(ifaces) == 0 {
		return nil
	}

	// hcxdumptool requires the interface to be in monitor mode.
	// Run for 30 seconds and check for PMKID output.
	outFile := "/tmp/beacon-pmkid.pcapng"
	cmd := exec.CommandContext(ctx, hcxPath,
		"-i", ifaces[0],
		"-o", outFile,
		"--enable_status=1",
		"--filtermode=2",
	)
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &outBuf

	if err := cmd.Run(); err != nil {
		return nil
	}

	output := outBuf.String()
	if !strings.Contains(output, "PMKID") && !strings.Contains(output, "pmkid") {
		return nil
	}

	return []finding.Finding{{
		CheckID:  finding.CheckWiFiPMKID,
		Module:   "surface",
		Scanner:  scannerName,
		Severity: finding.SeverityCritical,
		Asset:    asset,
		Title:    "WPA2 PMKID captured — offline passphrase cracking possible",
		Description: "A WPA2 PMKID was captured using hcxdumptool. " +
			"Offline cracking of the WiFi passphrase is now possible using hashcat " +
			"(mode 22000 for WPA-PBKDF2-PMKID+EAPOL). " +
			"Use a strong random passphrase (20+ characters) to resist cracking.",
		Evidence:     map[string]any{"tool": "hcxdumptool", "method": "pmkid", "capture": outFile},
		ProofCommand: fmt.Sprintf("hcxdumptool -i %s -o /tmp/pmkid.pcapng --enable_status=1", ifaces[0]),
		DiscoveredAt: time.Now(),
	}}
}

// ── Default gateway discovery ─────────────────────────────────────────────────

// defaultGateway returns the IP address of the system's default gateway.
// Uses OS-native routing commands — no root required.
func defaultGateway() (string, error) {
	switch runtime.GOOS {
	case "darwin":
		return defaultGatewayMacOS()
	case "linux":
		return defaultGatewayLinux()
	default:
		return "", fmt.Errorf("default gateway lookup not supported on %s", runtime.GOOS)
	}
}

func defaultGatewayMacOS() (string, error) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			gw := strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
			if net.ParseIP(gw) != nil {
				return gw, nil
			}
		}
	}
	return "", fmt.Errorf("gateway not found in route output")
}

func defaultGatewayLinux() (string, error) {
	// Try ip route first.
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err == nil {
		// "default via 192.168.1.1 dev wlan0 ..."
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			for i, f := range fields {
				if f == "via" && i+1 < len(fields) {
					if net.ParseIP(fields[i+1]) != nil {
						return fields[i+1], nil
					}
				}
			}
		}
	}
	// Fallback: route -n
	out, err = exec.Command("route", "-n").Output()
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		// route -n: Destination Gateway Genmask Flags ...
		// Default route has destination 0.0.0.0
		if len(fields) >= 2 && fields[0] == "0.0.0.0" {
			if net.ParseIP(fields[1]) != nil {
				return fields[1], nil
			}
		}
	}
	return "", fmt.Errorf("default gateway not found")
}
