// Package nas implements a deep-mode scanner for NAS appliances (Synology,
// TrueNAS, QNAP). It probes vendor-specific REST APIs to detect SMBv1,
// unencrypted management, default credentials, public shares, outdated
// firmware, SSH root login, missing snapshot protection, and iSCSI without
// CHAP authentication.
package nas

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan"
)

const scannerName = "onprem/nas"

// Config holds NAS appliance connection parameters.
type Config struct {
	Endpoint      string // NAS management URL (e.g., "https://nas.local:5001")
	Username      string
	Password      string
	NASType       string // "auto", "synology", "truenas", "qnap"
	SkipTLSVerify bool
}

// Scanner probes NAS appliances for security misconfigurations.
type Scanner struct {
	cfg    Config
	client *http.Client
}

// New returns a new Scanner with the given configuration.
func New(cfg Config, client *http.Client) *Scanner {
	if client == nil {
		tr := &http.Transport{}
		if cfg.SkipTLSVerify {
			tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
	}
	return &Scanner{cfg: cfg, client: client}
}

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// --------------------------------------------------------------------------
// NAS type detection
// --------------------------------------------------------------------------

type nasType int

const (
	nasUnknown  nasType = iota
	nasSynology
	nasTrueNAS
	nasQNAP
)

func (n nasType) String() string {
	switch n {
	case nasSynology:
		return "synology"
	case nasTrueNAS:
		return "truenas"
	case nasQNAP:
		return "qnap"
	default:
		return "unknown"
	}
}

// --------------------------------------------------------------------------
// Run
// --------------------------------------------------------------------------

// Run executes the NAS appliance scanner. Requires Deep mode because it
// authenticates and queries vendor APIs. The scan-type gate is enforced by
// the on-prem module dispatcher; this method assumes deep or authorized mode.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	endpoint := s.cfg.Endpoint
	if endpoint == "" {
		scheme := "https"
		if sctx, ok := scan.FromContext(ctx); ok {
			scheme = sctx.Scheme()
		}
		endpoint = scheme + "://" + asset
	}
	endpoint = strings.TrimRight(endpoint, "/")

	var findings []finding.Finding

	// Check if management is over plain HTTP (no TLS).
	if strings.HasPrefix(endpoint, "http://") {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckOnpremNASNoTLS,
			Scanner:  scannerName,
			Severity: finding.SeverityMedium,
			Title:    fmt.Sprintf("NAS management UI at %s uses plain HTTP (no TLS)", endpoint),
			Description: fmt.Sprintf(
				"The NAS management interface at %s is accessed over plain HTTP. "+
					"Administrative credentials and session tokens are transmitted in "+
					"cleartext, enabling eavesdropping and credential theft.",
				endpoint,
			),
			Asset:        asset,
			ProofCommand: fmt.Sprintf("curl -sI '%s'", endpoint),
			Evidence: map[string]any{
				"endpoint": endpoint,
				"protocol": "http",
			},
			DiscoveredAt: time.Now(),
		})
	}

	// Detect NAS type.
	detected := s.detectType(ctx, endpoint)
	if detected == nasUnknown {
		findings = append(findings, finding.Finding{
			CheckID:      finding.CheckOnpremNASScanError,
			Scanner:      scannerName,
			Severity:     finding.SeverityInfo,
			Title:        fmt.Sprintf("NAS type could not be detected at %s", endpoint),
			Description:  fmt.Sprintf("Could not identify the NAS appliance type at %s. Tried Synology DSM, TrueNAS, and QNAP QTS detection endpoints.", endpoint),
			Asset:        asset,
			ProofCommand: fmt.Sprintf("curl -sk '%s/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query'", endpoint),
			Evidence: map[string]any{
				"endpoint": endpoint,
			},
			DiscoveredAt: time.Now(),
		})
		return findings, nil
	}

	// Run vendor-specific checks.
	switch detected {
	case nasSynology:
		findings = append(findings, s.scanSynology(ctx, endpoint, asset)...)
	case nasTrueNAS:
		findings = append(findings, s.scanTrueNAS(ctx, endpoint, asset)...)
	case nasQNAP:
		findings = append(findings, s.scanQNAP(ctx, endpoint, asset)...)
	}

	return findings, nil
}

// --------------------------------------------------------------------------
// Type detection
// --------------------------------------------------------------------------

func (s *Scanner) detectType(ctx context.Context, endpoint string) nasType {
	// Honor explicit config.
	switch strings.ToLower(s.cfg.NASType) {
	case "synology":
		return nasSynology
	case "truenas":
		return nasTrueNAS
	case "qnap":
		return nasQNAP
	}

	// Auto-detect by probing known endpoints.
	// Synology DSM.
	if body, status := s.httpGet(ctx, endpoint+"/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query"); status == http.StatusOK {
		if strings.Contains(string(body), "SYNO.") {
			return nasSynology
		}
	}

	// TrueNAS.
	if body, status := s.httpGet(ctx, endpoint+"/api/v2.0/system/info"); status == http.StatusOK || status == http.StatusUnauthorized {
		if strings.Contains(string(body), "TrueNAS") || strings.Contains(string(body), "FreeNAS") || status == http.StatusOK {
			return nasTrueNAS
		}
	}

	// QNAP QTS.
	if _, status := s.httpGet(ctx, endpoint+"/cgi-bin/authLogin.cgi"); status == http.StatusOK {
		return nasQNAP
	}

	return nasUnknown
}

// --------------------------------------------------------------------------
// Synology DSM scanning
// --------------------------------------------------------------------------

func (s *Scanner) scanSynology(ctx context.Context, endpoint, asset string) []finding.Finding {
	var findings []finding.Finding

	// Check firmware version.
	if body, status := s.httpGet(ctx, endpoint+"/webapi/entry.cgi?api=SYNO.DSM.Info&version=2&method=getinfo"); status == http.StatusOK {
		var resp struct {
			Data struct {
				Version       string `json:"version_string"`
				Model         string `json:"model"`
				SMBEnabled    bool   `json:"smb_enabled"`
				SMBv1Enabled  bool   `json:"smb1_enabled"`
				SSHEnabled    bool   `json:"ssh_enabled"`
			} `json:"data"`
			Success bool `json:"success"`
		}
		if err := json.Unmarshal(body, &resp); err == nil && resp.Success {
			// Outdated firmware check.
			if resp.Data.Version != "" && isSynologyOutdated(resp.Data.Version) {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckOnpremNASOutdatedFirmware,
					Scanner:  scannerName,
					Severity: finding.SeverityHigh,
					Title:    fmt.Sprintf("Synology NAS %s runs outdated DSM %s", resp.Data.Model, resp.Data.Version),
					Description: fmt.Sprintf(
						"Synology NAS %s at %s runs DSM %s which has known CVEs. "+
							"Update to the latest DSM version to patch known vulnerabilities.",
						resp.Data.Model, endpoint, resp.Data.Version,
					),
					Asset:        asset,
					ProofCommand: fmt.Sprintf("curl -sk '%s/webapi/entry.cgi?api=SYNO.DSM.Info&version=2&method=getinfo'", endpoint),
					Evidence: map[string]any{
						"nas_type": "synology",
						"model":    resp.Data.Model,
						"version":  resp.Data.Version,
					},
					DiscoveredAt: time.Now(),
				})
			}

			// SMBv1 check.
			if resp.Data.SMBv1Enabled {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckOnpremNASSMBv1,
					Scanner:  scannerName,
					Severity: finding.SeverityHigh,
					Title:    fmt.Sprintf("Synology NAS at %s has SMBv1 enabled", asset),
					Description: fmt.Sprintf(
						"Synology NAS at %s has SMBv1 protocol enabled. SMBv1 is vulnerable "+
							"to EternalBlue (CVE-2017-0144), WannaCry, and NotPetya attacks. "+
							"Disable SMBv1 in Control Panel > File Services.",
						endpoint,
					),
					Asset:        asset,
					ProofCommand: fmt.Sprintf("curl -sk '%s/webapi/entry.cgi?api=SYNO.DSM.Info&version=2&method=getinfo' | jq .data.smb1_enabled", endpoint),
					Evidence: map[string]any{
						"nas_type":     "synology",
						"smb1_enabled": true,
					},
					DiscoveredAt: time.Now(),
				})
			}

			// SSH root login check.
			if resp.Data.SSHEnabled {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckOnpremNASSSHRoot,
					Scanner:  scannerName,
					Severity: finding.SeverityMedium,
					Title:    fmt.Sprintf("Synology NAS at %s has SSH enabled", asset),
					Description: fmt.Sprintf(
						"Synology NAS at %s has SSH enabled. Synology DSM allows root "+
							"login via SSH by default. Disable SSH or restrict root login.",
						endpoint,
					),
					Asset:        asset,
					ProofCommand: fmt.Sprintf("ssh -o BatchMode=yes root@%s exit 2>&1 || true", asset),
					Evidence: map[string]any{
						"nas_type":    "synology",
						"ssh_enabled": true,
					},
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	// Check for default admin credentials.
	findings = append(findings, s.checkDefaultCreds(ctx, endpoint, asset, "synology")...)

	// Check for public/anonymous shares.
	findings = append(findings, s.checkSynologyShares(ctx, endpoint, asset)...)

	// Check snapshot protection.
	findings = append(findings, s.checkSynologySnapshots(ctx, endpoint, asset)...)

	// Check iSCSI CHAP.
	findings = append(findings, s.checkSynologyISCSI(ctx, endpoint, asset)...)

	return findings
}

// --------------------------------------------------------------------------
// TrueNAS scanning
// --------------------------------------------------------------------------

func (s *Scanner) scanTrueNAS(ctx context.Context, endpoint, asset string) []finding.Finding {
	var findings []finding.Finding

	// Authenticate with API key or basic auth.
	authHeader := s.truenasAuthHeader()

	// Check system info and version.
	if body, status := s.httpGetWithAuth(ctx, endpoint+"/api/v2.0/system/info", authHeader); status == http.StatusOK {
		var info struct {
			Version  string `json:"version"`
			Hostname string `json:"hostname"`
		}
		if err := json.Unmarshal(body, &info); err == nil {
			if info.Version != "" && isTrueNASOutdated(info.Version) {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckOnpremNASOutdatedFirmware,
					Scanner:  scannerName,
					Severity: finding.SeverityHigh,
					Title:    fmt.Sprintf("TrueNAS at %s runs outdated version %s", asset, info.Version),
					Description: fmt.Sprintf(
						"TrueNAS at %s runs version %s which has known CVEs. "+
							"Update to the latest TrueNAS release.",
						endpoint, info.Version,
					),
					Asset:        asset,
					ProofCommand: fmt.Sprintf("curl -sk -H 'Authorization: Basic ***' '%s/api/v2.0/system/info'", endpoint),
					Evidence: map[string]any{
						"nas_type": "truenas",
						"version":  info.Version,
						"hostname": info.Hostname,
					},
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	// Check SMB shares for guest access.
	if body, status := s.httpGetWithAuth(ctx, endpoint+"/api/v2.0/sharing/smb", authHeader); status == http.StatusOK {
		var shares []struct {
			Name      string `json:"name"`
			Path      string `json:"path"`
			GuestOK   bool   `json:"guestok"`
			Enabled   bool   `json:"enabled"`
		}
		if err := json.Unmarshal(body, &shares); err == nil {
			for _, share := range shares {
				if share.Enabled && share.GuestOK {
					findings = append(findings, finding.Finding{
						CheckID:  finding.CheckOnpremNASPublicShares,
						Scanner:  scannerName,
						Severity: finding.SeverityHigh,
						Title:    fmt.Sprintf("TrueNAS SMB share '%s' allows guest access", share.Name),
						Description: fmt.Sprintf(
							"TrueNAS SMB share '%s' (path: %s) at %s allows guest/anonymous "+
								"access. Any user on the network can read (and potentially write) "+
								"files without authentication.",
							share.Name, share.Path, endpoint,
						),
						Asset:        asset,
						ProofCommand: fmt.Sprintf("smbclient -N '//%s/%s' -c ls", asset, share.Name),
						Evidence: map[string]any{
							"nas_type":   "truenas",
							"share_name": share.Name,
							"share_path": share.Path,
							"guest_ok":   true,
						},
						DiscoveredAt: time.Now(),
					})
				}
			}

			// Check for SMBv1 in any share configuration.
			for _, share := range shares {
				if share.Enabled {
					// TrueNAS exposes SMB protocol version in service config, not per-share.
					// We check the service-level config below.
					break
				}
			}
		}
	}

	// Check NFS shares for public exports.
	if body, status := s.httpGetWithAuth(ctx, endpoint+"/api/v2.0/sharing/nfs", authHeader); status == http.StatusOK {
		var nfsShares []struct {
			Path    string   `json:"path"`
			Enabled bool     `json:"enabled"`
			Hosts   []string `json:"hosts"`
			Network []string `json:"network"`
		}
		if err := json.Unmarshal(body, &nfsShares); err == nil {
			for _, share := range nfsShares {
				if share.Enabled && len(share.Hosts) == 0 && len(share.Network) == 0 {
					findings = append(findings, finding.Finding{
						CheckID:  finding.CheckOnpremNASPublicShares,
						Scanner:  scannerName,
						Severity: finding.SeverityHigh,
						Title:    fmt.Sprintf("TrueNAS NFS export '%s' has no access restrictions", share.Path),
						Description: fmt.Sprintf(
							"TrueNAS NFS export '%s' at %s has no host or network restrictions. "+
								"Any machine on the network can mount this export.",
							share.Path, endpoint,
						),
						Asset:        asset,
						ProofCommand: fmt.Sprintf("showmount -e %s", asset),
						Evidence: map[string]any{
							"nas_type":    "truenas",
							"nfs_path":    share.Path,
							"hosts":       share.Hosts,
							"networks":    share.Network,
							"unrestricted": true,
						},
						DiscoveredAt: time.Now(),
					})
				}
			}
		}
	}

	// Check SMB service config for SMBv1.
	if body, status := s.httpGetWithAuth(ctx, endpoint+"/api/v2.0/smb", authHeader); status == http.StatusOK {
		var smbConfig struct {
			SMB1     bool   `json:"enable_smb1"`
			Protocol string `json:"server_min_protocol"`
		}
		if err := json.Unmarshal(body, &smbConfig); err == nil {
			if smbConfig.SMB1 || strings.Contains(strings.ToLower(smbConfig.Protocol), "smb1") || strings.Contains(strings.ToLower(smbConfig.Protocol), "nt1") {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckOnpremNASSMBv1,
					Scanner:  scannerName,
					Severity: finding.SeverityHigh,
					Title:    fmt.Sprintf("TrueNAS at %s has SMBv1 enabled", asset),
					Description: fmt.Sprintf(
						"TrueNAS at %s has SMBv1 protocol enabled. SMBv1 is vulnerable to "+
							"EternalBlue and WannaCry attacks. Set minimum protocol to SMB2.",
						endpoint,
					),
					Asset:        asset,
					ProofCommand: fmt.Sprintf("curl -sk -H 'Authorization: Basic ***' '%s/api/v2.0/smb'", endpoint),
					Evidence: map[string]any{
						"nas_type":     "truenas",
						"smb1_enabled": true,
						"min_protocol": smbConfig.Protocol,
					},
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	// Check SSH service for root login.
	if body, status := s.httpGetWithAuth(ctx, endpoint+"/api/v2.0/ssh", authHeader); status == http.StatusOK {
		var sshConfig struct {
			RootLogin bool `json:"rootlogin"`
		}
		if err := json.Unmarshal(body, &sshConfig); err == nil && sshConfig.RootLogin {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckOnpremNASSSHRoot,
				Scanner:  scannerName,
				Severity: finding.SeverityMedium,
				Title:    fmt.Sprintf("TrueNAS at %s allows SSH root login", asset),
				Description: fmt.Sprintf(
					"TrueNAS at %s has SSH root login enabled. Disable root login "+
						"and use a regular user account with sudo.",
					endpoint,
				),
				Asset:        asset,
				ProofCommand: fmt.Sprintf("ssh -o BatchMode=yes root@%s exit 2>&1 || true", asset),
				Evidence: map[string]any{
					"nas_type":   "truenas",
					"root_login": true,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	// Check iSCSI CHAP authentication.
	if body, status := s.httpGetWithAuth(ctx, endpoint+"/api/v2.0/iscsi/target", authHeader); status == http.StatusOK {
		var targets []struct {
			Name string `json:"name"`
			Auth string `json:"auth"`
		}
		if err := json.Unmarshal(body, &targets); err == nil {
			for _, t := range targets {
				if t.Auth == "" || strings.ToLower(t.Auth) == "none" {
					findings = append(findings, finding.Finding{
						CheckID:  finding.CheckOnpremNASiSCSINoAuth,
						Scanner:  scannerName,
						Severity: finding.SeverityHigh,
						Title:    fmt.Sprintf("iSCSI target '%s' has no CHAP authentication", t.Name),
						Description: fmt.Sprintf(
							"TrueNAS iSCSI target '%s' at %s has no CHAP authentication configured. "+
								"Any initiator on the network can connect to and mount this target. "+
								"Configure mutual CHAP authentication.",
							t.Name, endpoint,
						),
						Asset:        asset,
						ProofCommand: fmt.Sprintf("iscsiadm -m discovery -t sendtargets -p %s", asset),
						Evidence: map[string]any{
							"nas_type":    "truenas",
							"target_name": t.Name,
							"auth":        t.Auth,
						},
						DiscoveredAt: time.Now(),
					})
				}
			}
		}
	}

	// Check snapshot tasks.
	if body, status := s.httpGetWithAuth(ctx, endpoint+"/api/v2.0/pool/snapshottask", authHeader); status == http.StatusOK {
		var tasks []any
		if err := json.Unmarshal(body, &tasks); err == nil && len(tasks) == 0 {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckOnpremNASNoSnapshotProtection,
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Title:    fmt.Sprintf("TrueNAS at %s has no snapshot tasks configured", asset),
				Description: fmt.Sprintf(
					"TrueNAS at %s has no periodic snapshot tasks configured. Without "+
						"immutable snapshots, ransomware can encrypt all data with no "+
						"recovery option.",
					endpoint,
				),
				Asset:        asset,
				ProofCommand: fmt.Sprintf("curl -sk -H 'Authorization: Basic ***' '%s/api/v2.0/pool/snapshottask'", endpoint),
				Evidence: map[string]any{
					"nas_type":       "truenas",
					"snapshot_tasks": 0,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	// Check default credentials.
	findings = append(findings, s.checkDefaultCreds(ctx, endpoint, asset, "truenas")...)

	return findings
}

// --------------------------------------------------------------------------
// QNAP QTS scanning
// --------------------------------------------------------------------------

func (s *Scanner) scanQNAP(ctx context.Context, endpoint, asset string) []finding.Finding {
	var findings []finding.Finding

	// Get system info.
	if body, status := s.httpGet(ctx, endpoint+"/cgi-bin/management/manaRequest.cgi?subfunc=sysinfo"); status == http.StatusOK {
		bodyStr := string(body)

		// Check firmware version.
		version := extractXMLValue(bodyStr, "version")
		model := extractXMLValue(bodyStr, "modelName")
		if version != "" && isQNAPOutdated(version) {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckOnpremNASOutdatedFirmware,
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Title:    fmt.Sprintf("QNAP NAS %s runs outdated QTS %s", model, version),
				Description: fmt.Sprintf(
					"QNAP NAS %s at %s runs QTS %s which has known CVEs including "+
						"DeadBolt ransomware vulnerabilities. Update to the latest QTS.",
					model, endpoint, version,
				),
				Asset:        asset,
				ProofCommand: fmt.Sprintf("curl -sk '%s/cgi-bin/management/manaRequest.cgi?subfunc=sysinfo'", endpoint),
				Evidence: map[string]any{
					"nas_type": "qnap",
					"model":    model,
					"version":  version,
				},
				DiscoveredAt: time.Now(),
			})
		}

		// Check SMBv1.
		if strings.Contains(bodyStr, "smb1") || strings.Contains(bodyStr, "SMB1") || strings.Contains(bodyStr, "<samba_smb1>1</samba_smb1>") {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckOnpremNASSMBv1,
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Title:    fmt.Sprintf("QNAP NAS at %s has SMBv1 enabled", asset),
				Description: fmt.Sprintf(
					"QNAP NAS at %s has SMBv1 protocol enabled. SMBv1 is vulnerable to "+
						"EternalBlue and WannaCry attacks. Disable in Control Panel > "+
						"Network & File Services > Win/Mac/NFS.",
					endpoint,
				),
				Asset:        asset,
				ProofCommand: fmt.Sprintf("nmap --script smb-protocols -p445 %s", asset),
				Evidence: map[string]any{
					"nas_type":     "qnap",
					"smb1_enabled": true,
				},
				DiscoveredAt: time.Now(),
			})
		}

		// Check SSH.
		if strings.Contains(bodyStr, "<ssh>1</ssh>") || strings.Contains(bodyStr, "ssh_enabled") {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckOnpremNASSSHRoot,
				Scanner:  scannerName,
				Severity: finding.SeverityMedium,
				Title:    fmt.Sprintf("QNAP NAS at %s has SSH enabled (root login possible)", asset),
				Description: fmt.Sprintf(
					"QNAP NAS at %s has SSH enabled. QNAP QTS allows root login via SSH. "+
						"Disable SSH or restrict root access.",
					endpoint,
				),
				Asset:        asset,
				ProofCommand: fmt.Sprintf("ssh -o BatchMode=yes admin@%s exit 2>&1 || true", asset),
				Evidence: map[string]any{
					"nas_type":    "qnap",
					"ssh_enabled": true,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	// Check default credentials.
	findings = append(findings, s.checkDefaultCreds(ctx, endpoint, asset, "qnap")...)

	return findings
}

// --------------------------------------------------------------------------
// Common checks
// --------------------------------------------------------------------------

// checkDefaultCreds tries common default credentials for the detected NAS type.
func (s *Scanner) checkDefaultCreds(ctx context.Context, endpoint, asset, nasTypeStr string) []finding.Finding {
	var findings []finding.Finding

	type cred struct {
		user string
		pass string
	}

	defaultCreds := map[string][]cred{
		"synology": {
			{user: "admin", pass: ""},
			{user: "admin", pass: "admin"},
		},
		"truenas": {
			{user: "root", pass: ""},
			{user: "root", pass: "root"},
			{user: "admin", pass: "admin"},
		},
		"qnap": {
			{user: "admin", pass: "admin"},
			{user: "admin", pass: ""},
		},
	}

	creds, ok := defaultCreds[nasTypeStr]
	if !ok {
		return findings
	}

	for _, c := range creds {
		if s.tryLogin(ctx, endpoint, nasTypeStr, c.user, c.pass) {
			displayPass := c.pass
			if displayPass == "" {
				displayPass = "(empty)"
			}
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckOnpremNASDefaultAdmin,
				Scanner:  scannerName,
				Severity: finding.SeverityCritical,
				Title:    fmt.Sprintf("NAS at %s accepts default credentials %s/%s", asset, c.user, displayPass),
				Description: fmt.Sprintf(
					"NAS appliance at %s accepts the default credential %s:%s. "+
						"An attacker can gain full administrative access to the NAS, "+
						"including all stored data, user accounts, and system configuration.",
					endpoint, c.user, displayPass,
				),
				Asset:        asset,
				ProofCommand: fmt.Sprintf("curl -sk '%s' -u '%s:%s'", endpoint, c.user, c.pass),
				Evidence: map[string]any{
					"nas_type": nasTypeStr,
					"username": c.user,
					"password": "(redacted)",
				},
				DiscoveredAt: time.Now(),
			})
			break // one default cred finding is enough
		}
	}

	return findings
}

// tryLogin attempts to authenticate with the given credentials.
func (s *Scanner) tryLogin(ctx context.Context, endpoint, nasTypeStr, user, pass string) bool {
	switch nasTypeStr {
	case "synology":
		url := fmt.Sprintf("%s/webapi/auth.cgi?api=SYNO.API.Auth&version=3&method=login&account=%s&passwd=%s", endpoint, user, pass)
		body, status := s.httpGet(ctx, url)
		if status == http.StatusOK {
			return strings.Contains(string(body), `"success":true`) || strings.Contains(string(body), `"success": true`)
		}
	case "truenas":
		body, status := s.httpGetWithBasicAuth(ctx, endpoint+"/api/v2.0/system/info", user, pass)
		return status == http.StatusOK && len(body) > 0
	case "qnap":
		url := fmt.Sprintf("%s/cgi-bin/authLogin.cgi?user=%s&pwd=%s", endpoint, user, pass)
		body, status := s.httpGet(ctx, url)
		if status == http.StatusOK {
			return strings.Contains(string(body), "<authPassed>1</authPassed>") || strings.Contains(string(body), `"authPassed":1`)
		}
	}
	return false
}

// --------------------------------------------------------------------------
// Synology-specific checks
// --------------------------------------------------------------------------

func (s *Scanner) checkSynologyShares(ctx context.Context, endpoint, asset string) []finding.Finding {
	var findings []finding.Finding

	body, status := s.httpGet(ctx, endpoint+"/webapi/entry.cgi?api=SYNO.FileStation.List&version=2&method=list_share")
	if status != http.StatusOK {
		return findings
	}

	var resp struct {
		Data struct {
			Shares []struct {
				Name       string `json:"name"`
				Path       string `json:"path"`
				Additional struct {
					Perm struct {
						ACLEnable bool `json:"acl_enable"`
						IsACLMode bool `json:"is_acl_mode"`
					} `json:"perm"`
				} `json:"additional"`
			} `json:"shares"`
		} `json:"data"`
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
		return findings
	}

	for _, share := range resp.Data.Shares {
		if !share.Additional.Perm.ACLEnable && !share.Additional.Perm.IsACLMode {
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckOnpremNASPublicShares,
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Title:    fmt.Sprintf("Synology share '%s' has no ACL", share.Name),
				Description: fmt.Sprintf(
					"Synology share '%s' (path: %s) at %s has no ACL configured. "+
						"Files may be accessible without proper authentication.",
					share.Name, share.Path, endpoint,
				),
				Asset:        asset,
				ProofCommand: fmt.Sprintf("smbclient -N '//%s/%s' -c ls", asset, share.Name),
				Evidence: map[string]any{
					"nas_type":   "synology",
					"share_name": share.Name,
					"share_path": share.Path,
					"acl_enable": false,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings
}

func (s *Scanner) checkSynologySnapshots(ctx context.Context, endpoint, asset string) []finding.Finding {
	var findings []finding.Finding

	body, status := s.httpGet(ctx, endpoint+"/webapi/entry.cgi?api=SYNO.Snapshot.Replication.List&version=1&method=list")
	if status != http.StatusOK {
		return findings
	}

	var resp struct {
		Data struct {
			Snapshots []any `json:"snapshots"`
			Total     int   `json:"total"`
		} `json:"data"`
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
		return findings
	}

	if resp.Data.Total == 0 && len(resp.Data.Snapshots) == 0 {
		findings = append(findings, finding.Finding{
			CheckID:  finding.CheckOnpremNASNoSnapshotProtection,
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Title:    fmt.Sprintf("Synology NAS at %s has no snapshot protection", asset),
			Description: fmt.Sprintf(
				"Synology NAS at %s has no snapshots configured. Without immutable "+
					"snapshots, ransomware can encrypt all data with no recovery option. "+
					"Enable Snapshot Replication in the Synology Package Center.",
				endpoint,
			),
			Asset:        asset,
			ProofCommand: fmt.Sprintf("curl -sk '%s/webapi/entry.cgi?api=SYNO.Snapshot.Replication.List&version=1&method=list'", endpoint),
			Evidence: map[string]any{
				"nas_type":  "synology",
				"snapshots": 0,
			},
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}

func (s *Scanner) checkSynologyISCSI(ctx context.Context, endpoint, asset string) []finding.Finding {
	var findings []finding.Finding

	body, status := s.httpGet(ctx, endpoint+"/webapi/entry.cgi?api=SYNO.ISCSIServer.Target.List&version=1&method=list")
	if status != http.StatusOK {
		return findings
	}

	var resp struct {
		Data struct {
			Targets []struct {
				Name     string `json:"name"`
				AuthType int    `json:"auth_type"`
			} `json:"targets"`
		} `json:"data"`
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
		return findings
	}

	for _, t := range resp.Data.Targets {
		if t.AuthType == 0 { // 0 = no auth
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckOnpremNASiSCSINoAuth,
				Scanner:  scannerName,
				Severity: finding.SeverityHigh,
				Title:    fmt.Sprintf("Synology iSCSI target '%s' has no CHAP authentication", t.Name),
				Description: fmt.Sprintf(
					"Synology iSCSI target '%s' at %s has no CHAP authentication. "+
						"Any initiator can connect to this target.",
					t.Name, endpoint,
				),
				Asset:        asset,
				ProofCommand: fmt.Sprintf("iscsiadm -m discovery -t sendtargets -p %s", asset),
				Evidence: map[string]any{
					"nas_type":    "synology",
					"target_name": t.Name,
					"auth_type":   0,
				},
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings
}

// --------------------------------------------------------------------------
// HTTP helpers
// --------------------------------------------------------------------------

func (s *Scanner) httpGet(ctx context.Context, url string) ([]byte, int) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, 0
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	return body, resp.StatusCode
}

func (s *Scanner) httpGetWithAuth(ctx context.Context, url, authHeader string) ([]byte, int) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	} else if s.cfg.Username != "" {
		req.SetBasicAuth(s.cfg.Username, s.cfg.Password)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, 0
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	return body, resp.StatusCode
}

func (s *Scanner) httpGetWithBasicAuth(ctx context.Context, url, user, pass string) ([]byte, int) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0
	}
	req.SetBasicAuth(user, pass)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, 0
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	return body, resp.StatusCode
}

func (s *Scanner) truenasAuthHeader() string {
	if s.cfg.Username != "" || s.cfg.Password != "" {
		return "" // use basic auth in httpGetWithAuth
	}
	return ""
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// extractXMLValue extracts a simple XML tag value from a string.
func extractXMLValue(body, tag string) string {
	start := strings.Index(body, "<"+tag+">")
	if start < 0 {
		return ""
	}
	start += len("<" + tag + ">")
	end := strings.Index(body[start:], "</"+tag+">")
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(body[start : start+end])
}

// Version comparison helpers — simplified checks against known vulnerable ranges.

func isSynologyOutdated(version string) bool {
	// DSM 6.x and earlier are EOL.
	return strings.HasPrefix(version, "6.") || strings.HasPrefix(version, "5.") || strings.HasPrefix(version, "4.")
}

func isTrueNASOutdated(version string) bool {
	lower := strings.ToLower(version)
	// TrueNAS 12.x and FreeNAS are EOL.
	return strings.Contains(lower, "freenas") || strings.HasPrefix(lower, "truenas-12") || strings.HasPrefix(lower, "11.")
}

func isQNAPOutdated(version string) bool {
	// QTS 4.x is vulnerable to DeadBolt.
	return strings.HasPrefix(version, "4.") || strings.HasPrefix(version, "3.")
}
