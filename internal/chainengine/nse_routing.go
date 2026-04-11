package chainengine

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/exploit"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/scanlog"
)

// nseScriptToServiceMap maps NSE (nmap script engine) script IDs to the
// exploit playbook service name. When an nmap finding contains one of these
// scripts in its evidence, the chain engine routes it to the matching
// exploit playbook.
var nseScriptToServiceMap = map[string]string{
	// SMB vulnerabilities
	"smb-vuln-ms17-010": "smb",
	"ms17-010":          "smb",
	"smb-vuln-ms08-067": "smb",
	"smb-os-discovery":  "smb",

	// TLS / SSL vulnerabilities
	"ssl-heartbleed": "apache", // TLS-level vulnerability, target the web server

	// HTTP vulnerabilities
	"http-shellshock":         "apache",
	"http-vuln-cve2017-5638":  "apache", // Struts RCE
	"http-vuln-cve2014-3120":  "elasticsearch",
	"http-vuln-cve2017-12617": "tomcat",

	// FTP
	"ftp-anon":    "ftp",
	"ftp-vsftpd-backdoor": "ftp",

	// DNS
	"dns-recursion": "dns",

	// SNMP
	"snmp-info": "snmp",

	// Database
	"mysql-empty-password": "mysql",
	"mongodb-info":         "mongodb",
	"redis-info":           "redis",

	// SSH
	"ssh2-enum-algos": "ssh",

	// RDP / VNC
	"rdp-vuln-ms12-020": "rdp",
	"vnc-info":          "vnc",

	// IPMI
	"ipmi-cipher-zero": "snmp", // IPMI often co-located with SNMP management
}

// nseScriptToService extracts the NSE script name from a finding's evidence
// and returns the exploit playbook service name. Returns "" if no mapping exists.
func nseScriptToService(f finding.Finding) string {
	scriptName, _ := f.Evidence["script"].(string)
	if scriptName == "" {
		return ""
	}
	scriptName = strings.ToLower(strings.TrimSpace(scriptName))
	if svc, ok := nseScriptToServiceMap[scriptName]; ok {
		return svc
	}
	return ""
}

// isExploitableNSEScript returns true if the nmap finding has a script
// that maps to a known exploit playbook.
func isExploitableNSEScript(f finding.Finding) bool {
	return nseScriptToService(f) != ""
}

// isNmapFinding returns true if the finding originated from an nmap scanner
// (check IDs prefixed with "nmap.").
func isNmapFinding(f finding.Finding) bool {
	return strings.HasPrefix(string(f.CheckID), "nmap.")
}

// nseToExploitChain routes NSE vulnerability findings to the appropriate
// exploit playbook based on the script name detected.
var nseToExploitChain = Chain{
	Name:        "nse_to_exploit",
	Description: "Route nmap NSE vulnerability detections to exploit playbooks for post-exploitation",
	Matches: func(f finding.Finding) bool {
		return isNmapFinding(f) && isExploitableNSEScript(f)
	},
	Execute: func(ctx context.Context, e *Engine, trigger finding.Finding) []finding.Finding {
		sl := scanlog.FromContext(ctx)
		moduleName := safetyModuleName("nse_to_exploit")
		if err := exploit.CheckSafety(moduleName, e.maxSafety); err != nil {
			log.Printf("[chain] safety gate blocked nse_to_exploit: %v", err)
			return nil
		}

		service := nseScriptToService(trigger)
		if service == "" {
			return nil
		}

		pb := lookupPlaybook(service)
		if pb == nil {
			log.Printf("[chain] nse_to_exploit: no playbook found for service %q", service)
			sl.ChainEvaluate(string(trigger.CheckID), trigger.Asset, "nse_script", "", 0)
			return nil
		}

		host, port := extractHostPort(trigger)
		if host == "" {
			log.Printf("[chain] nse_to_exploit: could not extract host from finding")
			return nil
		}

		// Use first default port from playbook if nmap didn't provide one.
		if port == 0 && len(pb.DefaultPorts) > 0 {
			port = pb.DefaultPorts[0]
		}

		scriptName, _ := trigger.Evidence["script"].(string)
		cveID, _ := trigger.Evidence["cve"].(string)
		sl.ChainEvaluate(string(trigger.CheckID), trigger.Asset, "nse_script", pb.Service+".yaml", len(pb.CVEExploits))
		log.Printf("[chain] WARNING: executing nse_to_exploit — routing NSE script %s to %s playbook against %s:%d",
			scriptName, service, host, port)

		makeF := func(checkID finding.CheckID, severity finding.Severity, title, description string, evidence map[string]any) finding.Finding {
			if evidence == nil {
				evidence = make(map[string]any)
			}
			evidence["chain"] = fmt.Sprintf("nse(%s) → %s exploit", scriptName, service)
			evidence["nse_script"] = scriptName
			evidence["triggered_by"] = trigger.CheckID
			if cveID != "" {
				evidence["trigger_cve"] = cveID
			}
			return finding.Finding{
				CheckID:      checkID,
				Module:       "chainengine",
				Scanner:      "chain:nse_to_exploit:" + service,
				Severity:     severity,
				Title:        title,
				Description:  description,
				Asset:        trigger.Asset,
				Evidence:     evidence,
				Confidence:   finding.ConfidenceVerified,
				Visibility:   finding.VisibilityAuthenticated,
				EnabledBy:    enabledByRef(trigger),
				ChainDepth:   trigger.ChainDepth + 1,
				DiscoveredAt: time.Now(),
			}
		}

		// Try CVE-specific exploit first if we have a CVE from the NSE finding.
		if cveID != "" {
			// Normalize CVE ID for playbook lookup (e.g. "CVE-2017-0144").
			normalizedCVE := strings.ToUpper(cveID)
			if cveFindings := exploit.RunCVEExploit(ctx, pb, normalizedCVE, host, port, makeF); len(cveFindings) > 0 {
				return cveFindings
			}
		}

		// Fall back to generic service exploitation (auth + enumeration steps).
		results := exploit.Run(ctx, pb, host, port, makeF, true)
		if len(results) == 0 {
			return nil
		}

		return results
	},
}
