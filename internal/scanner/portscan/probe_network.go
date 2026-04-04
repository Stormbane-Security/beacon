package portscan

import (
	"context"
	"fmt"
	"strings"

	"github.com/stormbane-security/beacon/internal/finding"
)

func init() {
	registerProbe(ServiceProbe{
		Name:         "ssh",
		Category:     ProbeCatBanner,
		DefaultPorts: []int{22},
		Detect:       detectSSH,
	})
	registerProbe(ServiceProbe{
		Name:         "ftp",
		Category:     ProbeCatBanner,
		DefaultPorts: []int{21},
		Detect:       detectFTP,
	})
	registerProbe(ServiceProbe{
		Name:         "telnet",
		Category:     ProbeCatBanner,
		DefaultPorts: []int{23},
		Detect:       detectTelnet,
	})
	registerProbe(ServiceProbe{
		Name:         "smtp",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{25, 587},
		Detect:       detectSMTP,
	})
	registerProbe(ServiceProbe{
		Name:         "ldap",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{389, 636},
		Detect:       detectLDAP,
	})
	registerProbe(ServiceProbe{
		Name:         "kerberos",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{88},
		Detect:       detectKerberos,
	})
	registerProbe(ServiceProbe{
		Name:         "dns",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{53},
		Detect:       detectDNS,
	})
	registerProbe(ServiceProbe{
		Name:         "smb",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{445},
		Detect:       detectSMB,
	})
	registerProbe(ServiceProbe{
		Name:         "bgp",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{179},
		Detect:       detectBGP,
	})
	registerProbe(ServiceProbe{
		Name:         "sip",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{5060, 5061},
		Detect:       detectSIP,
	})
	registerProbe(ServiceProbe{
		Name:         "rtsp",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{554},
		Detect:       detectRTSP,
	})
	registerProbe(ServiceProbe{
		Name:         "iscsi",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{3260},
		Detect:       detectISCSI,
	})
	registerProbe(ServiceProbe{
		Name:         "rdp",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{3389},
		Detect:       detectRDP,
	})
	registerProbe(ServiceProbe{
		Name:         "vnc",
		Category:     ProbeCatBanner,
		DefaultPorts: []int{5900},
		Detect:       detectVNC,
	})
	registerProbe(ServiceProbe{
		Name:         "winrm",
		Category:     ProbeCatHTTP,
		DefaultPorts: []int{5985, 5986},
		Detect:       detectWinRM,
	})
	registerProbe(ServiceProbe{
		Name:         "imap",
		Category:     ProbeCatBanner,
		DefaultPorts: []int{143, 993},
		Detect:       detectIMAP,
	})
	registerProbe(ServiceProbe{
		Name:         "pop3",
		Category:     ProbeCatBanner,
		DefaultPorts: []int{110, 995},
		Detect:       detectPOP3,
	})
	registerProbe(ServiceProbe{
		Name:         "global-catalog",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{3268, 3269},
		Detect:       detectGlobalCatalog,
	})
	registerProbe(ServiceProbe{
		Name:         "epmd",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{4369},
		Detect:       detectEPMD,
	})
	registerProbe(ServiceProbe{
		Name:         "wins",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{1512},
		Detect:       detectWINS,
	})
	registerProbe(ServiceProbe{
		Name:         "rpcbind",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{111},
		Detect:       detectRPCBind,
	})
	registerProbe(ServiceProbe{
		Name:         "netconf",
		Category:     ProbeCatBanner,
		DefaultPorts: []int{830},
		Detect:       detectNETCONF,
	})
	registerProbe(ServiceProbe{
		Name:         "ajp-tomcat",
		Category:     ProbeCatProtocol,
		DefaultPorts: []int{8009},
		Detect:       detectAJPTomcat,
	})
}

func detectSSH(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if !strings.HasPrefix(banner, "SSH-") {
		return nil
	}
	ev := map[string]any{"port": port, "service": "ssh", "banner": banner}
	sv := parseSSHVersion(banner)
	if sv != "" {
		ev["ssh_software"] = sv
	}
	// Vendor detection via SSH banner.
	var netDevFindings []finding.Finding
	lsv := strings.ToLower(sv + " " + banner)
	switch {
	case strings.Contains(lsv, "cisco"):
		netDevFindings = append(netDevFindings, makeF(
			finding.CheckNetDeviceCiscoDetected,
			finding.SeverityInfo,
			"Cisco network device identified via SSH banner",
			"The SSH banner indicates this is a Cisco IOS, NX-OS, or ASA device. "+
				"Cisco network equipment commonly has SSH/Telnet management, SNMP, and HTTP management interfaces. "+
				"Check for default credentials, known CVEs, and unnecessary management protocol exposure.",
			ev,
		))
	case strings.Contains(lsv, "junos") || strings.Contains(lsv, "juniper"):
		netDevFindings = append(netDevFindings, makeF(
			finding.CheckNetDeviceJuniperDetected,
			finding.SeverityInfo,
			"Juniper JunOS network device identified via SSH banner",
			"The SSH banner indicates this is a Juniper Networks device running JunOS. "+
				"Check for NETCONF (port 830), J-Web management interface, and SNMP exposure.",
			ev,
		))
	case strings.Contains(lsv, "rosssh") || strings.Contains(lsv, "mikrotik"):
		netDevFindings = append(netDevFindings, makeF(
			finding.CheckNetDeviceMikroTikDetected,
			finding.SeverityInfo,
			"MikroTik RouterOS device identified via SSH banner",
			"The SSH banner (ROSSSH) indicates this is a MikroTik RouterOS device. "+
				"Check for Winbox protocol on port 8291, web management on port 80/8080, and API on port 8728. "+
				"MikroTik CVE-2018-14847 (Winbox credential disclosure) is widely exploited.",
			ev,
		))
	case strings.Contains(lsv, "flowssh") || strings.Contains(lsv, "fortigate") || strings.Contains(lsv, "fortigatessh"):
		netDevFindings = append(netDevFindings, makeF(
			finding.CheckNetDeviceFortinetDetected,
			finding.SeverityInfo,
			"Fortinet FortiGate device identified via SSH banner",
			"The SSH banner indicates this is a Fortinet FortiGate firewall. "+
				"Check for SSL VPN at /remote/login, web management at /login, and FortiOS CVEs.",
			ev,
		))
	case strings.Contains(lsv, "huawei") || strings.Contains(lsv, "vrp"):
		netDevFindings = append(netDevFindings, makeF(
			finding.CheckNetDeviceHuaweiDetected,
			finding.SeverityInfo,
			"Huawei VRP network device identified via SSH banner",
			"The SSH banner indicates this is a Huawei network device running VRP. "+
				"Check for web management interface (eNSP/iMaster) and NETCONF on port 830.",
			ev,
		))
	case strings.Contains(lsv, "erlang"):
		netDevFindings = append(netDevFindings, makeF(
			finding.CheckCVEErlangOTPSSH,
			finding.SeverityCritical,
			"Erlang/OTP SSH server detected — CVE-2025-32433 unauthenticated RCE",
			"The SSH banner indicates this server runs Erlang/OTP's built-in SSH daemon. "+
				"CVE-2025-32433 (CVSS 10.0, KEV-listed) allows unauthenticated pre-auth remote code execution "+
				"on unpatched Erlang/OTP versions prior to OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. "+
				"RabbitMQ, CouchDB, Riak, and custom Erlang services commonly use this SSH implementation. "+
				"Update Erlang/OTP immediately and restrict SSH access to trusted networks.",
			ev,
		))
	}

	// CVE-2018-15473: OpenSSH < 7.7 username enumeration via malformed public-key auth packet.
	if isOpenSSHUsernameEnumVulnerable(sv) {
		netDevFindings = append(netDevFindings, makeF(
			finding.CheckCVEOpenSSHUsernameEnum,
			finding.SeverityMedium,
			fmt.Sprintf("CVE-2018-15473: OpenSSH %s vulnerable to username enumeration", sv),
			fmt.Sprintf("OpenSSH %s is in the range vulnerable to CVE-2018-15473 (OpenSSH < 7.7p1). "+
				"An unauthenticated attacker can distinguish valid from invalid usernames by observing "+
				"the server response difference to a malformed public-key auth request: valid users cause "+
				"a connection reset while invalid users receive a standard auth failure response. "+
				"This enables targeted brute-force attacks against confirmed valid accounts. "+
				"Upgrade to OpenSSH 7.7p1 or later.", sv),
			ev,
		))
	}

	// CVE-2024-6387 (regreSSHion): OpenSSH 8.5p1–9.7p1 on Linux/glibc.
	if isOpenSSHRegreSSHionVulnerable(sv, banner) {
		netDevFindings = append(netDevFindings, makeF(
			finding.CheckCVEOpenSSHRegreSSHion,
			finding.SeverityHigh,
			fmt.Sprintf("CVE-2024-6387 (regreSSHion): OpenSSH %s may be vulnerable to unauthenticated RCE", sv),
			fmt.Sprintf(
				"SSH banner reports %s, which is in the CVE-2024-6387 vulnerable range (8.5p1–9.7p1). "+
					"regreSSHion is a signal-handler race condition in OpenSSH's SIGALRM handler that can "+
					"lead to pre-authentication unauthenticated remote code execution as root on glibc-based "+
					"Linux systems. Exploitation requires sustained effort (~10,000 attempts over hours). "+
					"Upgrade to OpenSSH 9.8p1 or later. Restrict SSH to known IP ranges as a defence-in-depth measure.",
				sv,
			),
			ev,
		))
	}

	sshFinding := makeF(
		finding.CheckPortSSHExposed,
		finding.SeverityHigh,
		fmt.Sprintf("SSH exposed on port %d", port),
		"SSH is publicly accessible. While SSH itself is secure when properly configured, "+
			"public exposure increases the attack surface for brute-force and credential-stuffing attacks.",
		ev,
	)
	return append(netDevFindings, sshFinding)
}

func detectFTP(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if !strings.HasPrefix(banner, "220 ") && !strings.HasPrefix(banner, "220-") {
		return nil
	}
	// Disambiguate: "220 " is shared by FTP and SMTP. Skip if it looks like SMTP.
	upper := strings.ToUpper(banner)
	if strings.Contains(upper, "SMTP") || strings.Contains(upper, "ESMTP") || strings.Contains(upper, "POSTFIX") || strings.Contains(upper, "SENDMAIL") {
		return nil
	}
	ev := map[string]any{"port": port, "service": "ftp", "banner": banner}
	fv := parseFTPVersion(banner)
	if fv != "" {
		ev["ftp_software"] = fv
	}
	// CVE-2011-2523: vsftpd 2.3.4 supply-chain backdoor.
	if fv == "vsFTPd 2.3.4" {
		return []finding.Finding{makeF(
			finding.CheckPortFTPVsftpdBackdoor,
			finding.SeverityCritical,
			fmt.Sprintf("vsftpd 2.3.4 detected on port %d — supply-chain backdoor (CVE-2011-2523)", port),
			"The FTP banner reports vsftpd 2.3.4, the exact version in which a supply-chain "+
				"backdoor was inserted into the official source tarball in July 2011. "+
				"The backdoor binds a root shell to TCP port 6200 when the username contains \":)\". "+
				"If this binary was installed from the compromised tarball (not a distro package), "+
				"the system is fully compromised. Replace vsftpd immediately and audit all accounts.",
			ev,
		)}
	}
	// CVE-2015-3306: ProFTPD 1.3.5 mod_copy unauthenticated arbitrary file read/write.
	if isProFTPDModCopyVulnerable(fv) {
		return []finding.Finding{makeF(
			finding.CheckCVEProFTPDModCopy,
			finding.SeverityCritical,
			fmt.Sprintf("ProFTPD 1.3.5 detected on port %d — mod_copy file read/write (CVE-2015-3306)", port),
			"The FTP banner reports ProFTPD 1.3.5, which is vulnerable to CVE-2015-3306 "+
				"(CVSS 10.0). The mod_copy module accepts SITE CPFR/CPTO commands from "+
				"unauthenticated clients, allowing arbitrary file reads and writes on the server. "+
				"This was exploited extensively to copy web shells into document roots. "+
				"Upgrade to ProFTPD 1.3.5a or later and disable mod_copy if not required.",
			ev,
		)}
	}

	// CVE-2025-47812: Wing FTP Server ≤ 7.4.3 pre-auth RCE (CISA KEV, CVSS 9.9).
	if wingVer := parseWingFTPVersion(banner); wingVer != "" {
		ev["wing_ftp_version"] = wingVer
		if isVulnerableWingFTP(wingVer) {
			return []finding.Finding{makeF(
				finding.CheckPortFTPWingRCE,
				finding.SeverityCritical,
				fmt.Sprintf("Wing FTP Server %s is vulnerable to CVE-2025-47812 (pre-auth RCE)", wingVer),
				"CVE-2025-47812 (CVSS 9.9, CISA KEV) is a pre-authentication remote code execution "+
					"vulnerability in Wing FTP Server ≤ 7.4.3. An unauthenticated attacker can execute "+
					"arbitrary OS commands as the service account. Upgrade to 7.4.4 or later immediately.",
				ev,
			)}
		}
	}
	// Active check: attempt anonymous FTP login.
	if probeFTPAnonymous(ctx, host, port) {
		evAnon := map[string]any{"port": port, "service": "ftp", "anonymous_login": true, "banner": banner}
		if fv != "" {
			evAnon["ftp_software"] = fv
		}
		return []finding.Finding{makeF(
			finding.CheckPortFTPAnonymous,
			finding.SeverityHigh,
			fmt.Sprintf("FTP anonymous login accepted on port %d", port),
			"The FTP server permits anonymous access (USER anonymous / PASS anonymous). "+
				"An unauthenticated attacker can list directories and potentially read or write files. "+
				"FTP anonymous login is often enabled for public file distribution but is frequently "+
				"misconfigured to expose internal files. Disable anonymous access or restrict write permissions.",
			evAnon,
		)}
	}
	return []finding.Finding{makeF(
		finding.CheckPortFTPExposed,
		finding.SeverityMedium,
		fmt.Sprintf("FTP exposed on port %d", port),
		"FTP transmits credentials and file content in plaintext. "+
			"Anonymous FTP access is common; even authenticated FTP is trivially intercepted.",
		ev,
	)}
}

func detectTelnet(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	// Telnet is identified by IAC sequences (0xFF prefix) or login/password prompts in the banner.
	if banner == "" {
		return nil
	}
	lb := strings.ToLower(banner)
	// Telnet IAC sequences: \xFF followed by WILL(0xFB), WONT(0xFC),
	// DO(0xFD), DONT(0xFE). A bare \xFF alone is too loose — many binary
	// protocols (MySQL, etc.) contain 0xFF bytes.
	hasIAC := strings.Contains(banner, "\xFF\xFB") ||
		strings.Contains(banner, "\xFF\xFC") ||
		strings.Contains(banner, "\xFF\xFD") ||
		strings.Contains(banner, "\xFF\xFE")
	hasTelnetSignal := hasIAC ||
		strings.Contains(lb, "login:") ||
		strings.Contains(lb, "username:") ||
		strings.Contains(lb, "user access verification") ||
		strings.Contains(lb, "mikrotik") ||
		strings.Contains(lb, "cisco") ||
		port == 23 // Fallback: standard telnet port with any banner
	if !hasTelnetSignal {
		return nil
	}
	ev := map[string]any{"port": port, "service": "telnet", "banner": banner}
	// Vendor identification from Telnet banner.
	if strings.Contains(lb, "user access verification") || strings.Contains(lb, "cisco ios") || strings.Contains(lb, "cisco nexus") {
		return []finding.Finding{
			makeF(finding.CheckNetDeviceCiscoDetected, finding.SeverityInfo,
				"Cisco network device identified via Telnet banner",
				"The Telnet banner contains 'User Access Verification', indicating a Cisco IOS or NX-OS device. "+
					"Telnet transmits credentials in plaintext. CVE-2023-20198 (CVSS 10.0) targets Cisco IOS XE web UI. "+
					"Disable Telnet and use SSH only.",
				ev),
			makeF(finding.CheckPortTelnetExposed, finding.SeverityHigh,
				fmt.Sprintf("Telnet exposed on port %d", port),
				"Telnet transmits all data including credentials in plaintext.",
				ev),
		}
	}
	if strings.Contains(lb, "mikrotik") {
		return []finding.Finding{
			makeF(finding.CheckNetDeviceMikroTikDetected, finding.SeverityInfo,
				"MikroTik RouterOS device identified via Telnet banner",
				"The Telnet banner identifies this as a MikroTik RouterOS device. "+
					"Default credentials (admin/<empty>) are extremely common. CVE-2018-14847 allows credential extraction via Winbox.",
				ev),
			makeF(finding.CheckPortTelnetExposed, finding.SeverityHigh,
				fmt.Sprintf("Telnet exposed on port %d", port),
				"Telnet transmits all data including credentials in plaintext.",
				ev),
		}
	}
	// CVE-2011-4862: BSD telnetd Kerberos encryption buffer overflow.
	if strings.Contains(banner, "\xFF\xFB\x26") || strings.Contains(banner, "\xFF\xFD\x26") {
		ev["telnet_encrypt_option"] = true
		return []finding.Finding{
			makeF(
				finding.CheckCVETelnetBSDEncrypt,
				finding.SeverityCritical,
				fmt.Sprintf("BSD telnetd with Kerberos ENCRYPT option detected on port %d — CVE-2011-4862", port),
				"The Telnet server offers IAC WILL/DO ENCRYPT (option 38) in its initial negotiation, "+
					"identifying this as BSD telnetd with Kerberos encryption support. "+
					"CVE-2011-4862 (CVSS 10.0) is a buffer overflow in the BSD telnetd AES key exchange handler "+
					"that allows an unauthenticated attacker to execute arbitrary code as root before login. "+
					"Affected: FreeBSD (all supported releases before 2011-12-23), NetBSD, and other BSD-derived systems. "+
					"Disable telnetd immediately and use SSH instead.",
				ev,
			),
			makeF(
				finding.CheckPortTelnetExposed,
				finding.SeverityHigh,
				fmt.Sprintf("Telnet exposed on port %d", port),
				"Telnet transmits all data including credentials in plaintext.",
				map[string]any{"port": port, "service": "telnet", "banner": banner},
			),
		}
	}
	// Check for GNU telnetd version — CVE-2026-32746 affects GNU telnetd ≤ 2.7.
	if ver := parseGNUTelnetdVersion(banner); ver != "" {
		ev["telnetd_version"] = ver
		if isVulnerableGNUTelnetd(ver) {
			return []finding.Finding{
				makeF(
					finding.CheckPortTelnetdVulnerable,
					finding.SeverityCritical,
					fmt.Sprintf("GNU telnetd %s exposed — vulnerable to pre-auth RCE (CVE-2026-32746)", ver),
					fmt.Sprintf(
						"GNU telnetd %s is internet-accessible and vulnerable to CVE-2026-32746 (CVSS 9.8). "+
							"A stack buffer overflow in the LINEMODE SLC option handler allows an unauthenticated attacker "+
							"to achieve remote code execution as root before the login prompt. "+
							"GNU inetutils ≤ 2.7 is affected. Disable telnet and use SSH instead.",
						ver),
					ev,
				),
				makeF(
					finding.CheckPortTelnetExposed,
					finding.SeverityHigh,
					fmt.Sprintf("Telnet exposed on port %d", port),
					"Telnet transmits all data including credentials in plaintext.",
					map[string]any{"port": port, "service": "telnet", "banner": banner},
				),
			}
		}
	}
	return []finding.Finding{makeF(
		finding.CheckPortTelnetExposed,
		finding.SeverityHigh,
		fmt.Sprintf("Telnet exposed on port %d", port),
		"Telnet transmits all data including credentials in plaintext. "+
			"Any network observer can capture authentication credentials and session content.",
		ev,
	)}
}

func detectSMTP(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	// Identify SMTP by banner content (220 greeting with SMTP/ESMTP keywords) or standard ports.
	upper := strings.ToUpper(banner)
	isSMTPBanner := strings.HasPrefix(banner, "220 ") && (strings.Contains(upper, "SMTP") || strings.Contains(upper, "ESMTP") ||
		strings.Contains(upper, "POSTFIX") || strings.Contains(upper, "SENDMAIL") || strings.Contains(upper, "EXIM"))
	if !isSMTPBanner && port != 25 && port != 587 {
		return nil
	}
	// Active check: open relay test.
	if probeSMTPOpenRelay(ctx, host, port) {
		return []finding.Finding{makeF(
			finding.CheckPortSMTPOpenRelay,
			finding.SeverityHigh,
			fmt.Sprintf("SMTP open relay — server forwards external mail without authentication on port %d", port),
			"The SMTP server accepted MAIL FROM and RCPT TO commands for two unrelated external domains "+
				"without requiring authentication. This makes it an open mail relay that can be abused to send "+
				"spam and phishing emails with a legitimate IP reputation. Open relays damage domain reputation, "+
				"cause IP blacklisting, and violate most acceptable-use policies. "+
				"Configure the MTA to require AUTH for outbound relay or restrict relay to trusted IPs.",
			map[string]any{"port": port, "service": "smtp", "banner": banner,
				"proof": fmt.Sprintf("telnet %s %d → EHLO test → MAIL FROM:<a@external1.com> → RCPT TO:<b@external2.com>", host, port)},
		)}
	}
	// Banner grab parsing for software/version.
	if banner != "" {
		lbanner := strings.ToLower(banner)
		if strings.Contains(lbanner, "exim") {
			eximVer := parseEximVersion(banner)
			ev := map[string]any{"port": port, "service": "smtp", "banner": banner, "exim_version": eximVer}

			// CVE-2018-6789: Exim < 4.90.1 base64d() off-by-one heap overflow → pre-auth RCE (KEV).
			if eximVer != "" && isEximHeapOverflowVulnerable(eximVer) {
				return []finding.Finding{makeF(
					finding.CheckCVEEximHeapOverflow,
					finding.SeverityCritical,
					fmt.Sprintf("CVE-2018-6789: Exim %s vulnerable to pre-auth heap overflow RCE on port %d", eximVer, port),
					fmt.Sprintf("Exim %s is internet-accessible and vulnerable to CVE-2018-6789 (CVSS 9.8, KEV). "+
						"A one-byte heap overflow in the base64d() decoder allows an unauthenticated remote attacker "+
						"to corrupt heap metadata and achieve arbitrary write, leading to remote code execution "+
						"as the Exim daemon user. All Exim versions before 4.90.1 are affected. "+
						"Exploited by multiple botnets. Upgrade to Exim 4.90.1 or later immediately.", eximVer),
					ev,
				)}
			}

			// CVE-2019-10149: Exim 4.87–4.91 local-part expansion RCE (KEV).
			if eximVer != "" && isEximRCE2019Vulnerable(eximVer) {
				return []finding.Finding{makeF(
					finding.CheckCVEEximRCE2019,
					finding.SeverityCritical,
					fmt.Sprintf("CVE-2019-10149: Exim %s vulnerable to unauthenticated RCE on port %d", eximVer, port),
					fmt.Sprintf("Exim %s is internet-accessible and vulnerable to CVE-2019-10149 (CVSS 9.8, KEV). "+
						"The DELIVER_FAIL_STR expansion in Exim 4.87–4.91 allows a remote attacker to execute "+
						"arbitrary OS commands by crafting a malicious local part in the RCPT TO address. "+
						"The vulnerability is exploited by sending a specially-crafted bounce message. "+
						"Exploited by the Gitpaste-12 botnet and multiple threat actors. "+
						"Upgrade to Exim 4.92 or later immediately.", eximVer),
					ev,
				)}
			}

			// CVE-2025-26794: Exim 4.98 < 4.98.1 SQL injection via ETRN (CVSS 9.8).
			return []finding.Finding{makeF(
				finding.CheckPortExImVulnerable,
				finding.SeverityCritical,
				fmt.Sprintf("Exim MTA exposed on port %d — verify CVE-2025-26794 (4.98 < 4.98.1)", port),
				"Exim SMTP server is internet-accessible. CVE-2025-26794 (CVSS 9.8) is an unauthenticated SQL injection "+
					"in Exim 4.98 before 4.98.1 via the ETRN serialization path. Verify version from banner and update immediately.",
				ev,
			)}
		}
		return []finding.Finding{makeF(
			finding.CheckPortSMTPExposed,
			finding.SeverityMedium,
			fmt.Sprintf("SMTP server exposed on port %d", port),
			"An SMTP server is publicly accessible. The banner may reveal internal hostnames, MTA software, and version. "+
				"Internet-facing SMTP is expected for mail delivery (port 25) but should be version-hardened. "+
				"Submission port 587 should require authentication (AUTH PLAIN/LOGIN over TLS only).",
			map[string]any{"port": port, "service": "smtp", "banner": banner},
		)}
	}
	return nil
}

func detectLDAP(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	// Attempt a null bind to retrieve rootDSE.
	if ldapInfo := probeLDAP(ctx, host, port); ldapInfo != nil {
		if isAD, _ := ldapInfo["is_active_directory"].(bool); isAD {
			return []finding.Finding{makeF(
				finding.CheckPortActiveDirectoryExposed,
				finding.SeverityCritical,
				fmt.Sprintf("Active Directory domain controller exposed via LDAP on port %d", port),
				"An Active Directory domain controller is accessible from the internet via LDAP. "+
					"The rootDSE responds to anonymous queries revealing the AD domain name, DC hostname, "+
					"and forest functional level. An internet-facing DC enables Kerberoasting, AS-REP roasting, "+
					"LDAP injection attacks, and NTLM relay. This is a critical security misconfiguration.",
				ldapInfo,
			)}
		}
		return []finding.Finding{makeF(
			finding.CheckPortLDAPExposed,
			finding.SeverityHigh,
			fmt.Sprintf("LDAP server accessible on port %d — anonymous rootDSE query succeeded", port),
			"An LDAP directory server is accessible from the internet and responds to anonymous queries. "+
				"The rootDSE reveals server software, naming contexts, and supported SASL mechanisms. "+
				"LDAP CVE-2025-26663 (CVSS 9.8) affects Windows LDAP and allows unauthenticated RCE.",
			ldapInfo,
		)}
	}
	if port == 636 {
		// LDAPS with no probe success — still report TLS LDAP exposure
		return []finding.Finding{makeF(
			finding.CheckPortLDAPExposed,
			finding.SeverityHigh,
			fmt.Sprintf("LDAPS server accessible on port %d", port),
			"An LDAP server with TLS is accessible from the internet. "+
				"Restrict LDAP access to internal networks and VPN clients only.",
			map[string]any{"port": port, "service": "ldap"},
		)}
	}
	return nil
}

func detectKerberos(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if !probeKerberos(ctx, host, port) {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortKerberosExposed,
		finding.SeverityHigh,
		"Kerberos KDC exposed on port 88",
		"A Kerberos Key Distribution Center (KDC) is accessible from the internet, indicating an Active Directory "+
			"domain controller is internet-exposed. This enables AS-REP roasting (accounts without pre-auth), "+
			"Kerberoasting (SPN enumeration), and brute-force of domain accounts without account lockout on older configs. "+
			"AD domain controllers should never be directly internet-accessible.",
		map[string]any{"port": port, "service": "kerberos", "banner": banner},
	)}
}

func detectDNS(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if !probeDNSTCP(ctx, host, port) {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortDNSVersionExposed,
		finding.SeverityLow,
		"DNS server exposed on TCP port 53",
		"A DNS server is accessible on TCP port 53. TCP DNS is used for zone transfers (AXFR) and large responses. "+
			"Open recursive resolvers enable amplification DDoS attacks. Check if AXFR is allowed (covered by dns scanner). "+
			"CVE-2025-40778 (BIND 9 cache poisoning, CVSS 8.6) affects BIND 9.11–9.21.",
		map[string]any{"port": port, "service": "dns"},
	)}
}

func detectSMB(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	// First verify SMB is actually running on this port by sending a negotiate
	// request to the scanned port (not hardcoded 445).
	if !probeSMBOnPort(ctx, host, port) {
		return nil
	}

	var findings []finding.Finding

	// Check 1: SMBv1 protocol enabled (probes the actual port).
	if probeSMBv1OnPort(ctx, host, port) {
		findings = append(findings, makeF(
			finding.CheckPortSMBv1Enabled,
			finding.SeverityCritical,
			"SMBv1 protocol accepted — EternalBlue/WannaCry risk (CVE-2017-0144)",
			"The SMB server accepted the SMBv1 ('NT LM 0.12') dialect when offered alongside SMBv2/3. "+
				"SMBv1 is an obsolete protocol with known critical vulnerabilities: "+
				"CVE-2017-0144 (EternalBlue/WannaCry, CVSS 8.1) exploits an SMBv1 buffer overflow for unauthenticated RCE on Windows. "+
				"CVE-2017-7494 (SambaCry) uses SMBv1 for shared-library injection on Linux Samba servers. "+
				"WannaCry and NotPetya both required SMBv1 for propagation. "+
				"Disable SMBv1: PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false. "+
				"Modern Windows (Server 2019+, Win10 1709+) disables SMBv1 by default.",
			map[string]any{"port": port, "service": "smb", "smb_v1": true},
		))
	}

	// Check 2: SMB null session (probes the actual port).
	if probeSMBNullSessionOnPort(ctx, host, port) {
		findings = append(findings,
			makeF(
				finding.CheckPortSMBNullSession,
				finding.SeverityCritical,
				"SMB null session accepted — unauthenticated share enumeration possible",
				"The SMB server accepted a null session (empty username and password). "+
					"An unauthenticated attacker can enumerate shares, users, and domain information "+
					"via NetShareEnum, NetUserEnum, and similar MSRPC calls. "+
					"Null sessions are a prerequisite for many lateral-movement and password-spray attacks. "+
					"Disable null sessions via: Group Policy → Network access: Restrict anonymous access to Named Pipes and Shares.",
				map[string]any{"port": port, "service": "smb", "null_session": true},
			),
		)
	}

	// Emit the base SMB-exposed finding.
	findings = append(findings, makeF(
		finding.CheckPortSMBExposed,
		finding.SeverityHigh,
		fmt.Sprintf("SMB exposed on port %d", port),
		"Server Message Block (SMB) is publicly accessible. "+
			"SMB has been the vector for major ransomware campaigns (WannaCry, NotPetya) and enables lateral movement.",
		map[string]any{"port": port, "service": "smb", "banner": banner},
	))
	return findings
}

func detectBGP(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if !probeBGP(ctx, host, port) {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortBGPExposed,
		finding.SeverityHigh,
		"BGP port 179 accessible from internet",
		"The Border Gateway Protocol (BGP) port is reachable from the internet. BGP is the core internet routing "+
			"protocol; internet-facing BGP sessions should only be established with known peers. "+
			"Exposed BGP allows session hijacking, route injection, and BGP hijacking attacks. "+
			"Restrict port 179 to known BGP peer IP addresses with firewall rules.",
		map[string]any{"port": port, "service": "bgp", "banner": banner},
	)}
}

func detectSIP(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	sipInfo := probeSIP(ctx, host, port)
	if sipInfo == "" {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortSIPExposed,
		finding.SeverityMedium,
		fmt.Sprintf("SIP server exposed on port %d", port),
		"A SIP (Session Initiation Protocol) server is publicly accessible. "+
			"Exposed SIP servers are targeted for toll fraud, eavesdropping, and credential brute-force. "+
			"Restrict access to known IP ranges or use a SIP proxy with authentication.",
		map[string]any{"port": port, "service": "sip", "sip_response": sipInfo, "banner": banner},
	)}
}

func detectRTSP(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	rtspInfo := probeRTSP(ctx, host, port)
	if rtspInfo == "" {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortRTSPExposed,
		finding.SeverityMedium,
		fmt.Sprintf("RTSP server exposed on port %d", port),
		"An RTSP (Real Time Streaming Protocol) server is publicly accessible. "+
			"This commonly indicates an internet-exposed IP camera or video streaming system. "+
			"Many RTSP servers have no authentication or use default credentials. "+
			"Restrict access to prevent unauthorized video surveillance access.",
		map[string]any{"port": port, "service": "rtsp", "rtsp_response": rtspInfo, "banner": banner},
	)}
}

func detectISCSI(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if isISCSI := probeISCSI(ctx, host, port); !isISCSI {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortISCSIExposed,
		finding.SeverityHigh,
		fmt.Sprintf("iSCSI target exposed on port %d", port),
		"An iSCSI storage target is publicly accessible. "+
			"iSCSI provides direct block-level access to storage. An internet-exposed iSCSI target "+
			"allows any initiator to mount the storage volume and access raw disk data, "+
			"potentially reading or destroying entire databases and filesystems. "+
			"Restrict access to trusted initiator IQNs and bind to private network interfaces only.",
		map[string]any{"port": port, "service": "iscsi", "banner": banner},
	)}
}

func detectRDP(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if !probeRDP(ctx, host, port) {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortRDPExposed,
		finding.SeverityCritical,
		fmt.Sprintf("RDP (Remote Desktop) exposed on port %d", port),
		"Remote Desktop Protocol is publicly accessible. "+
			"RDP has a history of critical vulnerabilities (BlueKeep, DejaBlue) and is a top ransomware entry vector.",
		map[string]any{"port": port, "service": "rdp", "banner": banner},
	)}
}

func detectVNC(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if !probeVNC(banner) {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortVNCExposed,
		finding.SeverityCritical,
		fmt.Sprintf("VNC exposed on port %d", port),
		"A VNC remote desktop server is publicly accessible. "+
			"VNC is frequently deployed without authentication and provides full graphical desktop access.",
		map[string]any{"port": port, "service": "vnc", "banner": banner},
	)}
}

func detectWinRM(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if !probeWinRM(ctx, host, port) {
		return nil
	}
	schemeName := "HTTP"
	if port == 5986 {
		schemeName = "HTTPS"
	}
	return []finding.Finding{makeF(
		finding.CheckPortWinRMExposed,
		finding.SeverityHigh,
		fmt.Sprintf("WinRM (%s) exposed on port %d", schemeName, port),
		"Windows Remote Management (WinRM/WSMan) is publicly accessible. "+
			"WinRM enables remote PowerShell execution and is a primary lateral-movement path for attackers "+
			"who obtain Windows credentials. Exposure is unusual for internet-facing hosts.",
		map[string]any{"port": port, "service": "winrm", "banner": banner},
	)}
}

func detectIMAP(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	// IMAP banners start with "* OK" (untagged OK response).
	isIMAPBanner := strings.HasPrefix(banner, "* OK") || strings.HasPrefix(banner, "* BYE")
	if !isIMAPBanner && port != 993 {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortIMAPExposed,
		finding.SeverityMedium,
		fmt.Sprintf("IMAP server exposed on port %d", port),
		"An IMAP mail server is publicly accessible. Internet-facing IMAP allows credential brute-force and "+
			"may expose mailbox contents if authentication is bypassed. Restrict to VPN access where possible.",
		map[string]any{"port": port, "service": "imap", "banner": banner},
	)}
}

func detectPOP3(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	// POP3 banners start with "+OK".
	isPOP3Banner := strings.HasPrefix(banner, "+OK")
	if !isPOP3Banner && port != 995 {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortPOP3Exposed,
		finding.SeverityMedium,
		fmt.Sprintf("POP3 server exposed on port %d", port),
		"A POP3 mail server is publicly accessible. POP3 is a legacy protocol; modern deployments should use IMAP or "+
			"restrict mail access behind a VPN. Exposed POP3 enables credential stuffing and brute-force attacks.",
		map[string]any{"port": port, "service": "pop3", "banner": banner},
	)}
}

func detectGlobalCatalog(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if !probeGlobalCatalog(ctx, host, port) {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortGlobalCatalogExposed,
		finding.SeverityHigh,
		fmt.Sprintf("Active Directory Global Catalog exposed on port %d", port),
		"An Active Directory Global Catalog port is accessible from the internet. "+
			"Global Catalog servers answer forest-wide LDAP queries. Exposure confirms an AD DC is internet-reachable. "+
			"Restrict to internal network access only.",
		map[string]any{"port": port, "service": "global-catalog"},
	)}
}

func detectEPMD(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	nodes := probeEPMD(ctx, host, port)
	if len(nodes) == 0 {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortEPMDExposed,
		finding.SeverityHigh,
		fmt.Sprintf("Erlang EPMD listing %d node(s) without authentication on port 4369", len(nodes)),
		"The Erlang Port Mapper Daemon (EPMD) is accessible from the internet and lists all running Erlang "+
			"nodes with their names and ports without authentication. Exposed nodes may include RabbitMQ, "+
			"CouchDB, or custom Erlang applications that accept unauthenticated inter-node connections. "+
			"CVE-2025-32433 affects Erlang/OTP SSH (port 22) with CVSS 10.0; EPMD exposure reveals the full cluster topology.",
		map[string]any{"port": port, "service": "epmd", "nodes": nodes},
	)}
}

func detectWINS(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if !probeWINS(ctx, host, port) {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortWINSExposed,
		finding.SeverityHigh,
		"WINS server exposed on port 1512",
		"A Windows Internet Name Service (WINS) server is accessible from the internet. "+
			"CVE-2025-10230 (CVSS 10.0) is an unauthenticated RCE in Samba WINS hook command injection — "+
			"affects Samba AD DCs with 'wins support = yes' and 'wins hook' configured. "+
			"WINS is a legacy NetBIOS name resolution service and should not be internet-accessible.",
		map[string]any{"port": port, "service": "wins"},
	)}
}

func detectRPCBind(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if !probeRPCBind(ctx, host, port) {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortRPCBindExposed,
		finding.SeverityMedium,
		"RPC portmapper exposed on port 111",
		"The Sun RPC portmapper is accessible from the internet. It responds to DUMP requests with a list of all "+
			"registered RPC services (NFS, NIS, lockd, mountd, etc.) and their ports — without authentication. "+
			"If NFS mountd is registered, NFS exports may be enumerable and mountable without credentials.",
		map[string]any{"port": port, "service": "rpcbind"},
	)}
}

func detectNETCONF(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if !probeNETCONF(banner) {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckPortNetconfExposed,
		finding.SeverityHigh,
		fmt.Sprintf("NETCONF network management port exposed on port %d", port),
		"NETCONF (RFC 6241) is a network device management protocol for reading and modifying "+
			"device configuration. An internet-accessible NETCONF port indicates a network device "+
			"(router, switch, firewall) with management access exposed to the internet. "+
			"NETCONF runs over SSH — check for weak credentials and known CVEs for the device vendor.",
		map[string]any{"port": port, "service": "netconf", "banner": banner},
	)}
}

func detectAJPTomcat(ctx context.Context, host string, port int, banner string, makeF findingMaker) []finding.Finding {
	if !probeAJP(ctx, host, port) {
		return nil
	}
	return []finding.Finding{makeF(
		finding.CheckCVETomcatGhostCat,
		finding.SeverityCritical,
		fmt.Sprintf("CVE-2020-1938: Tomcat AJP connector exposed on port %d (GhostCat)", port),
		"The Apache Tomcat AJP (Apache JServ Protocol) connector is publicly accessible on port 8009. "+
			"CVE-2020-1938 (CVSS 9.8, KEV, GhostCat) allows an unauthenticated attacker to read any "+
			"file from the Tomcat webapp directory. When file upload is possible, this escalates to "+
			"unauthenticated remote code execution. AJP is an internal connector protocol designed "+
			"for communication between Tomcat and a front-end web server (Apache httpd) — it must "+
			"never be exposed to the internet. Disable the AJP connector in server.xml "+
			"(comment out or delete the Connector port=\"8009\" element) and apply all Tomcat patches.",
		map[string]any{"port": port, "service": "ajp", "protocol": "AJP/1.3"},
	)}
}
