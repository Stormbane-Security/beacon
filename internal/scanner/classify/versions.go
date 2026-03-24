package classify

// CheckVersions inspects the ServiceVersions extracted from an asset's HTTP
// headers and service banners and emits findings for known EOL or critically
// outdated software. Detection is purely passive — no extra requests are made.
//
// Why this matters: outdated software versions are directly correlated with
// known CVEs. A Server: Apache/2.2.x header narrows the CVE surface to a set
// of unpatched vulnerabilities from 2017 and earlier.

import (
	"fmt"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/playbook"
)

// eolEntry describes a known end-of-life or critically outdated software version.
type eolEntry struct {
	// prefix is the case-insensitive substring to match in a ServiceVersions value
	prefix string
	// label is the human-readable software name
	label string
	// eolDate is approximate end-of-life date (used in description)
	eolDate string
	// cveNote is a notable CVE or risk summary for this version range
	cveNote string
}

// eolSoftware maps ServiceVersions keys to lists of EOL version prefixes.
// Values are matched as case-insensitive prefix/contains against the version string.
var eolSoftware = map[string][]eolEntry{
	"web_server": {
		// Apache httpd
		{prefix: "apache/1.", label: "Apache httpd 1.x", eolDate: "2010", cveNote: "numerous unpatched CVEs; no longer supported"},
		{prefix: "apache/2.0.", label: "Apache httpd 2.0", eolDate: "2013", cveNote: "EOL; CVE-2011-3192, many others unpatched"},
		{prefix: "apache/2.2.", label: "Apache httpd 2.2", eolDate: "2017", cveNote: "EOL; CVE-2017-9788, CVE-2017-7679, many others unpatched"},
		{prefix: "apache/2.4.4", label: "Apache httpd 2.4.x (old)", eolDate: "2022", cveNote: "multiple patched CVEs; upgrade to 2.4.58+"},
		{prefix: "apache/2.4.5", label: "Apache httpd 2.4.x (old)", eolDate: "2023", cveNote: "CVE-2023-25690 (mod_proxy smuggling); upgrade to 2.4.58+"},
		// nginx EOL stable branches (odd minor = development, even = stable)
		{prefix: "nginx/0.", label: "nginx 0.x", eolDate: "2012", cveNote: "EOL; many unpatched vulnerabilities"},
		{prefix: "nginx/1.0.", label: "nginx 1.0", eolDate: "2012", cveNote: "EOL"},
		{prefix: "nginx/1.2.", label: "nginx 1.2", eolDate: "2014", cveNote: "EOL"},
		{prefix: "nginx/1.4.", label: "nginx 1.4", eolDate: "2015", cveNote: "EOL"},
		{prefix: "nginx/1.6.", label: "nginx 1.6", eolDate: "2016", cveNote: "EOL"},
		{prefix: "nginx/1.8.", label: "nginx 1.8", eolDate: "2016", cveNote: "EOL"},
		{prefix: "nginx/1.10.", label: "nginx 1.10", eolDate: "2017", cveNote: "EOL"},
		{prefix: "nginx/1.12.", label: "nginx 1.12", eolDate: "2018", cveNote: "EOL"},
		{prefix: "nginx/1.14.", label: "nginx 1.14", eolDate: "2019", cveNote: "EOL"},
		{prefix: "nginx/1.16.", label: "nginx 1.16", eolDate: "2021", cveNote: "EOL"},
		{prefix: "nginx/1.18.", label: "nginx 1.18", eolDate: "2022", cveNote: "EOL"},
		{prefix: "nginx/1.20.", label: "nginx 1.20", eolDate: "2023", cveNote: "EOL"},
		// Microsoft IIS
		{prefix: "microsoft-iis/5.", label: "Microsoft IIS 5.x", eolDate: "2010", cveNote: "EOL; Windows Server 2000/XP era"},
		{prefix: "microsoft-iis/6.", label: "Microsoft IIS 6.0", eolDate: "2015", cveNote: "EOL; CVE-2017-7269 (buffer overflow, actively exploited)"},
		{prefix: "microsoft-iis/7.", label: "Microsoft IIS 7.x", eolDate: "2020", cveNote: "EOL; Windows Server 2008 era"},
		{prefix: "microsoft-iis/8.", label: "Microsoft IIS 8.x", eolDate: "2020", cveNote: "EOL; Windows Server 2012 era"},
	},
	"powered_by": {
		// PHP EOL branches
		{prefix: "php/4.", label: "PHP 4.x", eolDate: "2008", cveNote: "EOL over 15 years; critically vulnerable"},
		{prefix: "php/5.", label: "PHP 5.x", eolDate: "2018", cveNote: "EOL; many unpatched CVEs"},
		{prefix: "php/7.0.", label: "PHP 7.0", eolDate: "2018", cveNote: "EOL"},
		{prefix: "php/7.1.", label: "PHP 7.1", eolDate: "2019", cveNote: "EOL"},
		{prefix: "php/7.2.", label: "PHP 7.2", eolDate: "2020", cveNote: "EOL"},
		{prefix: "php/7.3.", label: "PHP 7.3", eolDate: "2021", cveNote: "EOL"},
		{prefix: "php/7.4.", label: "PHP 7.4", eolDate: "2022", cveNote: "EOL since Dec 2022"},
		{prefix: "php/8.0.", label: "PHP 8.0", eolDate: "2023", cveNote: "EOL since Nov 2023"},
	},
}

// CheckVersions compares the versions extracted from an asset's evidence
// against the EOL table and returns findings for any outdated software.
// It adds zero extra network requests — evidence is from classify.Collect().
func CheckVersions(ev playbook.Evidence, asset string) []finding.Finding {
	if len(ev.ServiceVersions) == 0 {
		return nil
	}

	var findings []finding.Finding
	now := time.Now()

	for key, versionStr := range ev.ServiceVersions {
		entries, ok := eolSoftware[key]
		if !ok {
			continue
		}
		lower := strings.ToLower(versionStr)
		for _, entry := range entries {
			if !strings.HasPrefix(lower, entry.prefix) {
				continue
			}
			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckVersionOutdated,
				Module:   "surface",
				Scanner:  "classify",
				Severity: finding.SeverityHigh,
				Asset:    asset,
				Title:    fmt.Sprintf("EOL software detected: %s", entry.label),
				Description: fmt.Sprintf(
					"The HTTP response from %s advertises %s, which reached end-of-life around %s "+
						"and is no longer receiving security patches. %s. "+
						"Running EOL software on an internet-facing asset is a high-risk misconfiguration.",
					asset, versionStr, entry.eolDate, entry.cveNote),
				Evidence:     map[string]any{"version_string": versionStr, "eol_date": entry.eolDate, "cve_note": entry.cveNote},
				DiscoveredAt: now,
			})
			break // one finding per version key is enough
		}
	}

	return findings
}

// EmitTechStackFinding returns a single CheckWebTechDetected finding summarising
// the detected technology stack for an asset. This is intentionally low-severity
// (Info) but its description gives Claude the tech context it needs to write
// stack-specific remediation for every other finding on this asset.
// Returns nil if no version information was detected.
func EmitTechStackFinding(ev playbook.Evidence, asset string) *finding.Finding {
	if len(ev.ServiceVersions) == 0 && ev.FaviconHash == "" {
		return nil
	}

	var parts []string
	order := []string{"web_server", "powered_by", "generator_meta", "generator",
		"cookie_tech", "aspnet_version", "aspnetmvc_version"}
	seen := map[string]bool{}
	for _, k := range order {
		if v, ok := ev.ServiceVersions[k]; ok && v != "" && !seen[v] {
			seen[v] = true
			parts = append(parts, v)
		}
	}

	// SSH/FTP software comes from the port scanner findings, not from classify —
	// include them if they appear in the asset's service versions too.
	for k, v := range ev.ServiceVersions {
		alreadyInOrder := false
		for _, o := range order {
			if o == k {
				alreadyInOrder = true
				break
			}
		}
		if !alreadyInOrder && v != "" && !seen[v] {
			seen[v] = true
			parts = append(parts, v)
		}
	}

	if len(parts) == 0 {
		return nil
	}

	stack := strings.Join(parts, ", ")
	f := finding.Finding{
		CheckID:  finding.CheckWebTechDetected,
		Module:   "surface",
		Scanner:  "classify",
		Severity: finding.SeverityInfo,
		Asset:    asset,
		Title:    fmt.Sprintf("Technology stack detected: %s", stack),
		Description: fmt.Sprintf(
			"Passive fingerprinting identified the following technology on %s: %s. "+
				"This information is used to focus vulnerability checks and provide "+
				"stack-specific remediation advice.",
			asset, stack),
		Evidence:     map[string]any{"versions": ev.ServiceVersions, "favicon_hash": ev.FaviconHash},
		DiscoveredAt: time.Now(),
	}
	return &f
}

// VersionNucleiTags returns Nuclei template tags that should be added based on
// the detected technologies in Evidence. This directly improves CVE coverage —
// e.g. detecting PHP means PHP-specific templates are queued.
func VersionNucleiTags(ev playbook.Evidence) []string {
	if len(ev.ServiceVersions) == 0 && ev.Title == "" && ev.Body512 == "" {
		return nil
	}

	seen := map[string]bool{}
	var tags []string

	add := func(tag string) {
		if !seen[tag] {
			seen[tag] = true
			tags = append(tags, tag)
		}
	}

	for key, val := range ev.ServiceVersions {
		lower := strings.ToLower(val)
		switch key {
		case "web_server":
			if strings.Contains(lower, "apache") {
				add("apache")
			}
			if strings.Contains(lower, "nginx") {
				add("nginx")
			}
			if strings.Contains(lower, "iis") || strings.Contains(lower, "microsoft-iis") {
				add("iis")
			}
			if strings.Contains(lower, "tomcat") {
				add("tomcat")
			}
			if strings.Contains(lower, "jetty") {
				add("jetty")
			}
			if strings.Contains(lower, "lighttpd") {
				add("lighttpd")
			}
		case "powered_by":
			if strings.Contains(lower, "php") {
				add("php")
			}
			if strings.Contains(lower, "asp.net") {
				add("asp.net")
			}
			if strings.Contains(lower, "express") {
				add("nodejs")
			}
			if strings.Contains(lower, "django") {
				add("django")
			}
			if strings.Contains(lower, "rails") {
				add("rails")
			}
		case "generator_meta", "generator":
			if strings.Contains(lower, "wordpress") {
				add("wordpress")
				add("wp")
			}
			if strings.Contains(lower, "joomla") {
				add("joomla")
			}
			if strings.Contains(lower, "drupal") {
				add("drupal")
			}
			if strings.Contains(lower, "magento") {
				add("magento")
			}
		case "cookie_tech":
			if strings.Contains(lower, "php") {
				add("php")
			}
			if strings.Contains(lower, "java") {
				add("java")
			}
			if strings.Contains(lower, "asp.net") {
				add("asp.net")
			}
			if strings.Contains(lower, "wordpress") {
				add("wordpress")
				add("wp")
			}
			if strings.Contains(lower, "laravel") {
				add("php")
				add("laravel")
			}
			if strings.Contains(lower, "django") {
				add("django")
			}
			if strings.Contains(lower, "coldfusion") {
				add("coldfusion")
			}
		}
	}

	// Platform tag from body/header-based detection (jenkins, grafana, kibana, etc.)
	if plat, ok := ev.ServiceVersions["platform"]; ok {
		switch strings.ToLower(plat) {
		case "jenkins":
			add("jenkins")
		case "grafana":
			add("grafana")
		case "kibana":
			add("kibana")
		case "prometheus":
			add("prometheus")
		case "confluence":
			add("confluence")
		case "jira":
			add("jira")
		case "gitlab":
			add("gitlab")
		case "gitea":
			add("gitea")
		case "nextcloud":
			add("nextcloud")
		case "swagger-ui":
			add("swagger")
		case "wordpress":
			add("wordpress")
			add("wp")
		case "drupal":
			add("drupal")
		case "ghost":
			add("ghost")
		case "shopify":
			add("shopify")
		}
	}

	// Also check Body512 / Title for common CMS signals not covered by headers
	bodyLower := strings.ToLower(ev.Body512)
	titleLower := strings.ToLower(ev.Title)
	combined := bodyLower + " " + titleLower
	if strings.Contains(combined, "wp-content") || strings.Contains(combined, "wp-includes") {
		add("wordpress")
		add("wp")
	}
	if strings.Contains(combined, "joomla") {
		add("joomla")
	}
	if strings.Contains(combined, "drupal") {
		add("drupal")
	}

	return tags
}
