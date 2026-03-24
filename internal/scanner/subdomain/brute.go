package subdomain

// bruteForceSubdomains resolves a curated list of common subdomain prefixes
// against the target domain in parallel, returning only those that resolve to
// an IP address. All queries are standard DNS lookups — identical to what any
// DNS resolver or search engine crawler performs.
//
// The wordlist covers the most commonly found subdomains in practice: dev/staging
// environments, admin panels, APIs, VPN gateways, monitoring tools, and CI/CD
// infrastructure. False positives are impossible: if a name resolves, it exists.

import (
	"context"
	"net"
	"strings"
	"sync"
)

// commonPrefixes is a curated list of ~160 subdomain prefixes frequently
// found during security assessments. Skips generic noise (www, mail) that
// passive DNS and crt.sh already return well.
var commonPrefixes = []string{
	// Development / staging environments
	"dev", "dev2", "development", "stage", "staging", "staging2",
	"test", "test2", "testing", "uat", "qa", "qa2", "sandbox",
	"demo", "preview", "beta", "alpha", "preprod", "pre",
	"prod", "production", "live",

	// Admin / management interfaces
	"admin", "admin2", "administrator", "manage", "management",
	"manager", "control", "dashboard", "panel", "cp", "cpanel",
	"webmin", "plesk", "whm",

	// Infrastructure
	"vpn", "vpn2", "remote", "gateway", "gw", "proxy",
	"lb", "load", "router", "firewall", "bastion",
	"ns1", "ns2", "ns3", "ns4",
	"mx", "mx1", "mx2", "smtp", "mail2", "imap", "pop",

	// Web / API services
	"api", "api2", "rest", "graphql", "ws", "websocket",
	"cdn", "cdn2", "assets", "static", "media", "img", "images",
	"files", "upload", "uploads", "download", "downloads",
	"docs", "docs2", "documentation", "help", "kb", "support",
	"blog", "news", "forum", "wiki", "portal",
	"shop", "store", "checkout", "cart",
	"app", "apps", "mobile", "m", "wap",
	"web", "web2", "www2", "www3",

	// Authentication / SSO
	"auth", "login", "sso", "saml", "oauth", "idp", "iam",
	"account", "accounts", "profile", "my",

	// Monitoring / observability
	"monitor", "monitoring", "status", "health",
	"grafana", "kibana", "prometheus", "alertmanager",
	"nagios", "zabbix", "datadog", "newrelic",
	"log", "logs", "logging", "trace", "traces", "metrics",

	// DevOps / CI/CD
	"git", "gitlab", "github", "gitea",
	"jenkins", "ci", "cicd", "build", "deploy",
	"jira", "confluence", "bitbucket", "sonar", "sonarqube",
	"artifactory", "nexus", "registry", "harbor",

	// Container / cloud infrastructure
	"docker", "k8s", "kubernetes", "rancher",
	"vault", "consul", "etcd", "nomad",
	"redis", "cache", "memcache",
	"elastic", "es", "elasticsearch", "opensearch",

	// Databases (management UIs)
	"db", "database", "mysql", "postgres", "mongo", "mongodb",
	"phpmyadmin", "pgadmin", "adminer",

	// Corporate / HR systems
	"intranet", "internal", "corp", "intra",
	"hr", "payroll", "erp", "crm", "helpdesk",
	"exchange", "owa", "outlook", "webmail",
	"extranet", "partner", "vendor",

	// Security
	"security", "siem", "splunk", "waf",

	// Backup / archive
	"backup", "old", "legacy", "archive",

	// Misc
	"server", "host", "node", "hub", "relay",
	"scheduler", "queue", "kafka", "rabbitmq",
	"survey", "forms", "form", "feedback",
	"analytics", "tracking", "pixel",
	"crm2", "cms",
}

// wildcardIPs resolves a deliberately random hostname under domain to detect
// wildcard DNS. If *.domain resolves, it returns the set of wildcard IPs so
// brute-force results can be filtered. Returns an empty set if no wildcard.
func wildcardIPs(ctx context.Context, domain string) map[string]struct{} {
	probe := "beacon-wildcard-probe-x7q2m5k8." + domain
	addrs, err := net.DefaultResolver.LookupHost(ctx, probe)
	if err != nil || len(addrs) == 0 {
		return nil
	}
	ips := make(map[string]struct{}, len(addrs))
	for _, a := range addrs {
		ips[a] = struct{}{}
	}
	return ips
}

// bruteForceSubdomains resolves each prefix in commonPrefixes against domain
// using parallel DNS lookups. Returns only prefixes that successfully resolve
// to IPs that are NOT part of a wildcard DNS response, so wildcard domains
// (e.g. *.example.com → 1.2.3.4) do not flood results with false positives.
// Uses a concurrency of 50 to stay fast without overwhelming local DNS.
func bruteForceSubdomains(ctx context.Context, domain string) []string {
	const concurrency = 50

	// Detect wildcard DNS before the main loop.
	wildcards := wildcardIPs(ctx, domain)

	type result struct {
		sub string
	}

	results := make(chan result, len(commonPrefixes))
	sem := make(chan struct{}, concurrency)

	var wg sync.WaitGroup
	for _, prefix := range commonPrefixes {
		prefix := prefix
		fqdn := prefix + "." + domain
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			// Fast cancellation check before the blocking DNS call.
			select {
			case <-ctx.Done():
				return
			default:
			}
			addrs, err := net.DefaultResolver.LookupHost(ctx, fqdn)
			if err != nil || len(addrs) == 0 {
				return
			}
			// Skip subdomains whose entire IP set matches the wildcard set —
			// they exist only because of the wildcard, not a real record.
			if len(wildcards) > 0 {
				allWild := true
				for _, a := range addrs {
					if _, ok := wildcards[a]; !ok {
						allWild = false
						break
					}
				}
				if allWild {
					return
				}
			}
			results <- result{sub: strings.ToLower(fqdn)}
		}()
	}

	wg.Wait()
	close(results)

	var found []string
	for r := range results {
		found = append(found, r.sub)
	}
	return found
}
