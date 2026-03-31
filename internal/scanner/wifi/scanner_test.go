package wifi

import (
	"testing"

	"github.com/stormbane/beacon/internal/finding"
)

// ── parseAirportOutput ────────────────────────────────────────────────────────

func TestParseAirportOutput_WPA2(t *testing.T) {
	raw := `                            SSID BSSID             RSSI CHANNEL HT CC SECURITY (auth/unicast/group)
                        HomeWifi 12:34:56:78:9a:bc  -45  6,+1   Y  US WPA2(PSK/AES/AES)
`
	nets := parseAirportOutput(raw)
	if len(nets) != 1 {
		t.Fatalf("expected 1 network, got %d", len(nets))
	}
	n := nets[0]
	if n.SSID != "HomeWifi" {
		t.Errorf("SSID = %q, want %q", n.SSID, "HomeWifi")
	}
	if n.BSSID != "12:34:56:78:9a:bc" {
		t.Errorf("BSSID = %q", n.BSSID)
	}
	if n.Security != "WPA2(PSK/AES/AES)" {
		t.Errorf("Security = %q, want WPA2", n.Security)
	}
}

func TestParseAirportOutput_Open(t *testing.T) {
	raw := `                            SSID BSSID             RSSI CHANNEL HT CC SECURITY (auth/unicast/group)
                      CoffeeShop aa:bb:cc:dd:ee:ff  -70  11      Y  US NONE
`
	nets := parseAirportOutput(raw)
	if len(nets) != 1 {
		t.Fatalf("expected 1 network, got %d", len(nets))
	}
	if nets[0].Security != "NONE" {
		t.Errorf("Security = %q, want NONE", nets[0].Security)
	}
}

func TestParseAirportOutput_SkipsHeader(t *testing.T) {
	raw := `                            SSID BSSID             RSSI CHANNEL HT CC SECURITY (auth/unicast/group)
`
	nets := parseAirportOutput(raw)
	if len(nets) != 0 {
		t.Errorf("expected 0 networks after header-only input, got %d", len(nets))
	}
}

func TestParseAirportOutput_ShortLineSkipped(t *testing.T) {
	raw := `short`
	nets := parseAirportOutput(raw)
	if len(nets) != 0 {
		t.Errorf("expected 0 networks for short line, got %d", len(nets))
	}
}

// ── parseNmcliOutput ──────────────────────────────────────────────────────────

func TestParseNmcliOutput_Basic(t *testing.T) {
	// nmcli escapes colons inside field values as \:
	raw := `HomeWifi:12\:34\:56\:78\:9a\:bc:75:WPA2
OpenNet:aa\:bb\:cc\:dd\:ee\:ff:60:
`
	nets := parseNmcliOutput(raw)
	if len(nets) != 2 {
		t.Fatalf("expected 2 networks, got %d", len(nets))
	}
	if nets[0].SSID != "HomeWifi" {
		t.Errorf("SSID[0] = %q", nets[0].SSID)
	}
	if nets[0].BSSID != "12:34:56:78:9a:bc" {
		t.Errorf("BSSID[0] = %q", nets[0].BSSID)
	}
	if nets[0].Security != "WPA2" {
		t.Errorf("Security[0] = %q, want WPA2", nets[0].Security)
	}
	if nets[1].SSID != "OpenNet" {
		t.Errorf("SSID[1] = %q", nets[1].SSID)
	}
}

func TestParseNmcliOutput_EscapedColon(t *testing.T) {
	// SSID "Corp\:Net" with an escaped colon
	raw := `Corp\:Net:de:ad:be:ef:00:11:80:WPA2
`
	nets := parseNmcliOutput(raw)
	if len(nets) != 1 {
		t.Fatalf("expected 1 network, got %d", len(nets))
	}
	if nets[0].SSID != `Corp:Net` {
		t.Errorf("SSID = %q, want %q", nets[0].SSID, `Corp:Net`)
	}
}

// ── assessNetwork ─────────────────────────────────────────────────────────────

func TestAssessNetwork_Open(t *testing.T) {
	n := wifiNetwork{SSID: "OpenNet", BSSID: "aa:bb:cc:dd:ee:ff", Security: "NONE"}
	findings := assessNetwork(n, "local")
	assertCheckID(t, findings, finding.CheckWiFiOpenNetwork)
}

func TestAssessNetwork_WEP(t *testing.T) {
	n := wifiNetwork{SSID: "OldNet", BSSID: "aa:bb:cc:dd:ee:ff", Security: "WEP"}
	findings := assessNetwork(n, "local")
	assertCheckID(t, findings, finding.CheckWiFiWEPNetwork)
}

func TestAssessNetwork_WPSEnabled(t *testing.T) {
	n := wifiNetwork{SSID: "RouterNet", BSSID: "aa:bb:cc:dd:ee:ff", Security: "WPA2(PSK/AES/AES)", WPS: true}
	findings := assessNetwork(n, "local")
	assertCheckID(t, findings, finding.CheckWiFiWPSEnabled)
}

func TestAssessNetwork_TKIP(t *testing.T) {
	n := wifiNetwork{SSID: "OldRouter", BSSID: "aa:bb:cc:dd:ee:ff", Security: "WPA2(PSK/TKIP/TKIP)"}
	findings := assessNetwork(n, "local")
	assertCheckID(t, findings, finding.CheckWiFiWPA2TKIP)
}

func TestAssessNetwork_WPA2AES_NoFindings(t *testing.T) {
	n := wifiNetwork{SSID: "SecureNet", BSSID: "aa:bb:cc:dd:ee:ff", Security: "WPA2(PSK/AES/AES)", WPS: false}
	findings := assessNetwork(n, "local")
	for _, f := range findings {
		if f.CheckID == finding.CheckWiFiOpenNetwork ||
			f.CheckID == finding.CheckWiFiWEPNetwork ||
			f.CheckID == finding.CheckWiFiWPSEnabled ||
			f.CheckID == finding.CheckWiFiWPA2TKIP {
			t.Errorf("unexpected finding %s for secure WPA2-AES network", f.CheckID)
		}
	}
}

func TestAssessNetwork_WPA3_NoFindings(t *testing.T) {
	n := wifiNetwork{SSID: "Modern", BSSID: "aa:bb:cc:dd:ee:ff", Security: "WPA3(SAE/AES/AES)", WPS: false}
	findings := assessNetwork(n, "local")
	if len(findings) != 0 {
		t.Errorf("expected no findings for WPA3 network, got %d", len(findings))
	}
}

// ── splitNmcliFields ──────────────────────────────────────────────────────────

func TestSplitNmcliFields_NoEscape(t *testing.T) {
	parts := splitNmcliFields("a:b:c:d")
	if len(parts) != 4 {
		t.Fatalf("expected 4 parts, got %d: %v", len(parts), parts)
	}
}

func TestSplitNmcliFields_EscapedColon(t *testing.T) {
	parts := splitNmcliFields(`a\:b:c:d:e`)
	if len(parts) != 4 {
		t.Fatalf("expected 4 parts, got %d: %v", len(parts), parts)
	}
	if parts[0] != "a:b" {
		t.Errorf("parts[0] = %q, want %q", parts[0], "a:b")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func assertCheckID(t *testing.T, findings []finding.Finding, id finding.CheckID) {
	t.Helper()
	for _, f := range findings {
		if f.CheckID == id {
			return
		}
	}
	t.Errorf("expected finding %s, got: %v", id, checkIDs(findings))
}

func checkIDs(findings []finding.Finding) []finding.CheckID {
	ids := make([]finding.CheckID, len(findings))
	for i, f := range findings {
		ids[i] = f.CheckID
	}
	return ids
}
