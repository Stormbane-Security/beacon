package portscan

import (
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
)

func TestInterpretNmapScript_SMBOSDiscovery(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 445, nmapScript{
		ID:     "smb-os-discovery",
		Output: "OS: Windows 10 Pro 19041; NetBIOS name: WORKSTATION; Domain: CORP; FQDN: workstation.corp.local",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].CheckID != finding.CheckNmapSMBOSDiscovery {
		t.Errorf("checkID = %q; want %q", fs[0].CheckID, finding.CheckNmapSMBOSDiscovery)
	}
}

func TestInterpretNmapScript_SSLCertExpired(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 443, nmapScript{
		ID:     "ssl-cert",
		Output: "Subject: commonName=expired.example.com\nNot valid after: 2024-01-01T00:00:00\nThis certificate has expired",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].CheckID != finding.CheckNmapSSLCertExpired {
		t.Errorf("checkID = %q; want %q", fs[0].CheckID, finding.CheckNmapSSLCertExpired)
	}
	if fs[0].Severity != finding.SeverityHigh {
		t.Errorf("severity = %v; want High", fs[0].Severity)
	}
}

func TestInterpretNmapScript_SSLCertInfo(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 443, nmapScript{
		ID:     "ssl-cert",
		Output: "Subject: commonName=example.com\nNot valid after: 2030-12-31",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].CheckID != finding.CheckNmapSSLCertInfo {
		t.Errorf("checkID = %q; want %q", fs[0].CheckID, finding.CheckNmapSSLCertInfo)
	}
}

func TestInterpretNmapScript_HTTPTitle(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 80, nmapScript{
		ID:     "http-title",
		Output: "Welcome to My Application",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].CheckID != finding.CheckNmapHTTPTitle {
		t.Errorf("checkID = %q; want %q", fs[0].CheckID, finding.CheckNmapHTTPTitle)
	}
}

func TestInterpretNmapScript_HTTPTitle_Empty(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 80, nmapScript{
		ID:     "http-title",
		Output: "",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 0 {
		t.Errorf("expected 0 findings for empty title, got %d", len(fs))
	}
}

func TestInterpretNmapScript_HTTPRobots(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 80, nmapScript{
		ID:     "http-robots.txt",
		Output: "/admin/\nDisallow: /secret/\nDisallow: /api/internal/",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].CheckID != finding.CheckNmapHTTPRobots {
		t.Errorf("checkID = %q; want %q", fs[0].CheckID, finding.CheckNmapHTTPRobots)
	}
}

func TestInterpretNmapScript_HTTPRobots_NoDisallow(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 80, nmapScript{
		ID:     "http-robots.txt",
		Output: "User-agent: *\nAllow: /",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 0 {
		t.Errorf("expected 0 findings with no Disallow, got %d", len(fs))
	}
}

func TestInterpretNmapScript_NetBIOS(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 137, nmapScript{
		ID:     "nbstat",
		Output: "NetBIOS name: SERVER01, NetBIOS user: <unknown>, NetBIOS MAC: aa:bb:cc:dd:ee:ff",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].CheckID != finding.CheckNmapNetBIOSInfo {
		t.Errorf("checkID = %q; want %q", fs[0].CheckID, finding.CheckNmapNetBIOSInfo)
	}
}

func TestInterpretNmapScript_SMTPCommands_VRFY(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 25, nmapScript{
		ID:     "smtp-commands",
		Output: "EHLO HELO VRFY EXPN SIZE HELP",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].CheckID != finding.CheckNmapSMTPCommands {
		t.Errorf("checkID = %q; want %q", fs[0].CheckID, finding.CheckNmapSMTPCommands)
	}
	if fs[0].Severity != finding.SeverityMedium {
		t.Errorf("severity = %v; want Medium", fs[0].Severity)
	}
}

func TestInterpretNmapScript_SMTPCommands_NoVRFY(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 25, nmapScript{
		ID:     "smtp-commands",
		Output: "EHLO HELO SIZE HELP",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 0 {
		t.Errorf("expected 0 findings without VRFY/EXPN, got %d", len(fs))
	}
}

func TestInterpretNmapScript_VNCNoAuth(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 5900, nmapScript{
		ID:     "vnc-info",
		Output: "Protocol version: 3.8\nSecurity types: None (no authentication required)",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].CheckID != finding.CheckNmapVNCInfo {
		t.Errorf("checkID = %q; want %q", fs[0].CheckID, finding.CheckNmapVNCInfo)
	}
	if fs[0].Severity != finding.SeverityHigh {
		t.Errorf("severity = %v; want High", fs[0].Severity)
	}
}

func TestInterpretNmapScript_RDPWeakEncryption(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 3389, nmapScript{
		ID:     "rdp-enum-encryption",
		Output: "Security layer: RDP Security Layer\nRDP Encryption level: Low",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].CheckID != finding.CheckNmapRDPEncryption {
		t.Errorf("checkID = %q; want %q", fs[0].CheckID, finding.CheckNmapRDPEncryption)
	}
}

func TestInterpretNmapScript_RDPWithNLA(t *testing.T) {
	// NLA enabled = no finding
	fs := interpretNmapScript("10.0.0.1", 3389, nmapScript{
		ID:     "rdp-enum-encryption",
		Output: "Security layer: CredSSP (NLA)\nRDP Encryption level: High",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 0 {
		t.Errorf("expected 0 findings with NLA/CredSSP, got %d", len(fs))
	}
}

func TestInterpretNmapScript_TelnetNoEncryption(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 23, nmapScript{
		ID:     "telnet-encryption",
		Output: "Telnet server does not support encryption: not supported",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].CheckID != finding.CheckNmapTelnetEncrypt {
		t.Errorf("checkID = %q; want %q", fs[0].CheckID, finding.CheckNmapTelnetEncrypt)
	}
}

func TestInterpretNmapScript_SMBSigningDisabled(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 445, nmapScript{
		ID:     "smb-security-mode",
		Output: "account_used: guest\nmessage_signing: disabled",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].CheckID != finding.CheckNmapSMBSigningOff {
		t.Errorf("checkID = %q; want %q", fs[0].CheckID, finding.CheckNmapSMBSigningOff)
	}
	if fs[0].Severity != finding.SeverityHigh {
		t.Errorf("severity = %v; want High", fs[0].Severity)
	}
}

func TestInterpretNmapScript_SMBSigningEnabled(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 445, nmapScript{
		ID:     "smb-security-mode",
		Output: "account_used: guest\nmessage_signing: enabled and required",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 0 {
		t.Errorf("expected 0 findings when signing enabled, got %d", len(fs))
	}
}

func TestInterpretNmapScript_HTTPMethods_Dangerous(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 80, nmapScript{
		ID:     "http-methods",
		Output: "Supported Methods: GET HEAD POST OPTIONS PUT DELETE",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].CheckID != finding.CheckNmapHTTPMethods {
		t.Errorf("checkID = %q; want %q", fs[0].CheckID, finding.CheckNmapHTTPMethods)
	}
	methods := fs[0].Evidence["methods"].([]string)
	if len(methods) != 2 {
		t.Errorf("expected 2 dangerous methods (PUT, DELETE), got %v", methods)
	}
}

func TestInterpretNmapScript_HTTPMethods_Safe(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 80, nmapScript{
		ID:     "http-methods",
		Output: "Supported Methods: GET HEAD POST OPTIONS",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 0 {
		t.Errorf("expected 0 findings for safe methods only, got %d", len(fs))
	}
}

func TestInterpretNmapScript_NTPMonlist(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 123, nmapScript{
		ID:     "ntp-monlist",
		Output: "Target is a clock: NTP monlist response with 100 entries",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].CheckID != finding.CheckNmapNTPMonlist {
		t.Errorf("checkID = %q; want %q", fs[0].CheckID, finding.CheckNmapNTPMonlist)
	}
	if fs[0].Severity != finding.SeverityHigh {
		t.Errorf("severity = %v; want High", fs[0].Severity)
	}
}

func TestInterpretNmapScript_SMTPOpenRelay(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 25, nmapScript{
		ID:     "smtp-open-relay",
		Output: "Server is an open relay (16/16 tests)",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].CheckID != finding.CheckNmapSMTPOpenRelay {
		t.Errorf("checkID = %q; want %q", fs[0].CheckID, finding.CheckNmapSMTPOpenRelay)
	}
	if fs[0].Severity != finding.SeverityCritical {
		t.Errorf("severity = %v; want Critical", fs[0].Severity)
	}
}

func TestInterpretNmapScript_MySQLEmptyPassword(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 3306, nmapScript{
		ID:     "mysql-empty-password",
		Output: "root account has empty password",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].CheckID != finding.CheckNmapMySQLNoPassword {
		t.Errorf("checkID = %q; want %q", fs[0].CheckID, finding.CheckNmapMySQLNoPassword)
	}
	if fs[0].Severity != finding.SeverityCritical {
		t.Errorf("severity = %v; want Critical", fs[0].Severity)
	}
}

func TestInterpretNmapScript_IPMICipherZero(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 623, nmapScript{
		ID:     "ipmi-cipher-zero",
		Output: "IPMI 2.0 cipher 0 is vulnerable",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].CheckID != finding.CheckNmapIPMICipherZero {
		t.Errorf("checkID = %q; want %q", fs[0].CheckID, finding.CheckNmapIPMICipherZero)
	}
}

func TestExtractField(t *testing.T) {
	tests := []struct {
		output string
		prefix string
		want   string
	}{
		{"commonName=example.com\nother=val", "commonName=", "example.com"},
		{"no match here", "commonName=", ""},
		{"key=value/more", "key=", "value"},
		{"key=value;next", "key=", "value"},
	}
	for _, tt := range tests {
		got := extractField(tt.output, tt.prefix)
		if got != tt.want {
			t.Errorf("extractField(%q, %q) = %q; want %q", tt.output, tt.prefix, got, tt.want)
		}
	}
}
