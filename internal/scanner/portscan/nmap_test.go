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

// ── New NSE script tests ────────────────────────────────────────────────────

func TestInterpretNmapScript_HTTPServerHeader(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 80, nmapScript{
		ID:     "http-server-header",
		Output: "Apache/2.4.49 (Unix)",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].CheckID != finding.CheckNmapHTTPServerHeader {
		t.Errorf("checkID = %q; want %q", fs[0].CheckID, finding.CheckNmapHTTPServerHeader)
	}
	if fs[0].Severity != finding.SeverityInfo {
		t.Errorf("severity = %v; want Info", fs[0].Severity)
	}
}

func TestInterpretNmapScript_HTTPHeaders_MissingSecurity(t *testing.T) {
	// Output missing several security headers
	fs := interpretNmapScript("10.0.0.1", 443, nmapScript{
		ID:     "http-headers",
		Output: "Date: Mon, 01 Jan 2024 00:00:00 GMT\nServer: nginx\nContent-Type: text/html",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].CheckID != finding.CheckNmapHTTPHeaders {
		t.Errorf("checkID = %q; want %q", fs[0].CheckID, finding.CheckNmapHTTPHeaders)
	}
	issues := fs[0].Evidence["missing_headers"].([]string)
	if len(issues) < 3 {
		t.Errorf("expected at least 3 missing headers, got %d: %v", len(issues), issues)
	}
}

func TestInterpretNmapScript_HTTPHeaders_AllPresent(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 443, nmapScript{
		ID:     "http-headers",
		Output: "X-Frame-Options: DENY\nX-Content-Type-Options: nosniff\nContent-Security-Policy: default-src 'self'\nStrict-Transport-Security: max-age=31536000",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 0 {
		t.Errorf("expected 0 findings when all security headers present, got %d", len(fs))
	}
}

func TestInterpretNmapScript_SSLEnumCiphers_Weak(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 443, nmapScript{
		ID:     "ssl-enum-ciphers",
		Output: "SSLv3:\n  ciphers:\n    TLS_RSA_EXPORT_WITH_RC4_40_MD5\nTLSv1.0:\n  ciphers:\n    TLS_RSA_WITH_AES_128_CBC_SHA",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].CheckID != finding.CheckNmapSSLEnumCiphers {
		t.Errorf("checkID = %q; want %q", fs[0].CheckID, finding.CheckNmapSSLEnumCiphers)
	}
	if fs[0].Severity != finding.SeverityHigh {
		t.Errorf("severity = %v; want High", fs[0].Severity)
	}
}

func TestInterpretNmapScript_SSLEnumCiphers_Strong(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 443, nmapScript{
		ID:     "ssl-enum-ciphers",
		Output: "TLSv1.2:\n  ciphers:\n    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\nTLSv1.3:\n  ciphers:\n    TLS_AES_256_GCM_SHA384",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 0 {
		t.Errorf("expected 0 findings for strong ciphers only, got %d", len(fs))
	}
}

func TestInterpretNmapScript_SSHHostKey_Weak(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 22, nmapScript{
		ID:     "ssh-hostkey",
		Output: "1024 aa:bb:cc:dd:ee:ff:00:11 (ssh-dss)\n2048 11:22:33:44:55:66:77:88 (ssh-rsa)",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].CheckID != finding.CheckNmapSSHHostKey {
		t.Errorf("checkID = %q; want %q", fs[0].CheckID, finding.CheckNmapSSHHostKey)
	}
	if fs[0].Severity != finding.SeverityHigh {
		t.Errorf("severity = %v; want High (DSA key)", fs[0].Severity)
	}
}

func TestInterpretNmapScript_SSHHostKey_Strong(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 22, nmapScript{
		ID:     "ssh-hostkey",
		Output: "256 aa:bb:cc:dd:ee:ff:00:11 (ecdsa-sha2-nistp256)\n256 11:22:33:44:55:66:77:88 (ssh-ed25519)",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding (info level), got %d", len(fs))
	}
	if fs[0].Severity != finding.SeverityInfo {
		t.Errorf("severity = %v; want Info for strong keys", fs[0].Severity)
	}
}

func TestInterpretNmapScript_HTTPAuth(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 80, nmapScript{
		ID:     "http-auth",
		Output: "HTTP/1.1 401 Unauthorized\n  Basic realm=\"Admin Panel\"",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].CheckID != finding.CheckNmapHTTPAuth {
		t.Errorf("checkID = %q; want %q", fs[0].CheckID, finding.CheckNmapHTTPAuth)
	}
	if fs[0].Evidence["auth_type"] != "Basic" {
		t.Errorf("auth_type = %v; want Basic", fs[0].Evidence["auth_type"])
	}
}

func TestInterpretNmapScript_Vulners(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 80, nmapScript{
		ID:     "vulners",
		Output: "cpe:/a:apache:http_server:2.4.49:\n  CVE-2021-41773  7.5  https://vulners.com/cve/CVE-2021-41773\n  CVE-2021-42013  9.8  https://vulners.com/cve/CVE-2021-42013",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].CheckID != finding.CheckNmapVulners {
		t.Errorf("checkID = %q; want %q", fs[0].CheckID, finding.CheckNmapVulners)
	}
	cves := fs[0].Evidence["cves"].([]string)
	if len(cves) != 2 {
		t.Errorf("expected 2 CVEs, got %d: %v", len(cves), cves)
	}
}

func TestInterpretNmapScript_Vulners_NoCVEs(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 80, nmapScript{
		ID:     "vulners",
		Output: "cpe:/a:apache:http_server:2.4.62:\n  No known vulnerabilities",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 0 {
		t.Errorf("expected 0 findings when no CVEs, got %d", len(fs))
	}
}

func TestInterpretNmapScript_HTTPCookieFlags(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 443, nmapScript{
		ID:     "http-cookie-flags",
		Output: "/:\n  JSESSIONID:\n    httponly flag is not set\n    secure flag is not set",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].CheckID != finding.CheckNmapHTTPCookieFlags {
		t.Errorf("checkID = %q; want %q", fs[0].CheckID, finding.CheckNmapHTTPCookieFlags)
	}
	if fs[0].Severity != finding.SeverityMedium {
		t.Errorf("severity = %v; want Medium", fs[0].Severity)
	}
}

func TestInterpretNmapScript_SMB2SecurityMode(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 445, nmapScript{
		ID:     "smb2-security-mode",
		Output: "2.0.2:\n  Message signing enabled but not required",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].CheckID != finding.CheckNmapSMB2SecurityMode {
		t.Errorf("checkID = %q; want %q", fs[0].CheckID, finding.CheckNmapSMB2SecurityMode)
	}
	if fs[0].Severity != finding.SeverityHigh {
		t.Errorf("severity = %v; want High", fs[0].Severity)
	}
}

func TestInterpretNmapScript_SMB2SecurityMode_Required(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 445, nmapScript{
		ID:     "smb2-security-mode",
		Output: "3.1.1:\n  Message signing enabled and required",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 0 {
		t.Errorf("expected 0 findings when signing required, got %d", len(fs))
	}
}

func TestInterpretNmapScript_MSSQLInfo(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 1433, nmapScript{
		ID:     "ms-sql-info",
		Output: "  Instance name: MSSQLSERVER\n  Version: 15.0.2000.5\n  TCP port: 1433",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].CheckID != finding.CheckNmapMSSQLInfo {
		t.Errorf("checkID = %q; want %q", fs[0].CheckID, finding.CheckNmapMSSQLInfo)
	}
	if fs[0].Severity != finding.SeverityHigh {
		t.Errorf("severity = %v; want High", fs[0].Severity)
	}
}

func TestInterpretNmapScript_MongoDBInfo(t *testing.T) {
	fs := interpretNmapScript("10.0.0.1", 27017, nmapScript{
		ID:     "mongodb-info",
		Output: "MongoDB Build info:\n  version: 4.4.6\n  gitVersion: abc123\n  OpenSSLVersion: OpenSSL 1.1.1k",
	}, "nmap -sV 10.0.0.1", time.Now())
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].CheckID != finding.CheckNmapMongoDBInfo {
		t.Errorf("checkID = %q; want %q", fs[0].CheckID, finding.CheckNmapMongoDBInfo)
	}
	if fs[0].Severity != finding.SeverityHigh {
		t.Errorf("severity = %v; want High", fs[0].Severity)
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
