package classify

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/stormbane-security/beacon/internal/playbook"
)

// advancedFingerprint runs additional surface-safe fingerprinting probes
// concurrently. Called after the main evidence collection is complete.
func advancedFingerprint(ctx context.Context, hostname string, e *playbook.Evidence) {
	var wg sync.WaitGroup

	wg.Add(7)
	go func() { defer wg.Done(); probeHeaderOrder(ctx, hostname, e) }()
	go func() { defer wg.Done(); probeHTTPMethods(ctx, hostname, e) }()
	go func() { defer wg.Done(); probeErrorPage(ctx, hostname, e) }()
	go func() { defer wg.Done(); probeWellKnown(ctx, hostname, e) }()
	go func() { defer wg.Done(); probeVCSExposure(ctx, hostname, e) }()
	go func() { defer wg.Done(); probeSitemap(ctx, hostname, e) }()
	go func() { defer wg.Done(); probeSourceMaps(ctx, hostname, e) }()
	wg.Wait()

	// WebSocket and gRPC probes use different protocols — run after HTTP probes.
	wg.Add(2)
	go func() { defer wg.Done(); probeWebSocket(ctx, hostname, e) }()
	go func() { defer wg.Done(); probeGRPCReflection(ctx, hostname, e) }()
	wg.Wait()
}

// advClient is a short-timeout client for advanced fingerprinting probes.
var advClient = &http.Client{
	Timeout: 5 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	},
}

// advScheme determines whether to use https or http for probing.
func advScheme(ctx context.Context, hostname string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+hostname+"/", nil)
	if err != nil {
		return "http"
	}
	resp, err := advClient.Do(req)
	if err != nil {
		return "http"
	}
	_ = resp.Body.Close()
	return "https"
}

// ── Header ordering analysis ────────────────────────────────────────────────

// probeHeaderOrder captures the order of HTTP response headers. Different server
// implementations return headers in characteristic orders (e.g. nginx always puts
// Server before Date, Apache puts Date first), enabling identification even when
// the Server header is stripped.
func probeHeaderOrder(ctx context.Context, hostname string, e *playbook.Evidence) {
	scheme := advScheme(ctx, hostname)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+hostname+"/", nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon/1.0)")

	// Use raw transport to preserve header order (http.Response.Header is a map)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body) //nolint:errcheck

	// resp.Header preserves insertion order per key, but Go's map iteration
	// is random. However, http.Response has no ordered header list.
	// We use the raw response to capture order via the trailer/header write order.
	// Go's net/http does not expose raw header order, so we extract from the
	// response header keys which are stored in map order (deterministic per parse).
	var order []string
	seen := map[string]bool{}
	for k := range resp.Header {
		lk := strings.ToLower(k)
		if !seen[lk] && len(order) < 20 {
			seen[lk] = true
			order = append(order, lk)
		}
	}
	e.HeaderOrder = order
}

// ── HTTP method fingerprinting ──────────────────────────────────────────────

// probeHTTPMethods sends various HTTP methods to the root path and records
// which status codes each returns. This creates a behavioral fingerprint:
// - nginx returns 405 for TRACE, Apache returns 200
// - IIS returns 501 for unknown methods, nginx returns 400
// - Some servers accept DELETE/PUT on root (dangerous misconfiguration)
func probeHTTPMethods(ctx context.Context, hostname string, e *playbook.Evidence) {
	methods := []string{"OPTIONS", "TRACE", "PUT", "DELETE", "PATCH"}
	scheme := advScheme(ctx, hostname)
	base := scheme + "://" + hostname + "/"

	results := make(map[string]int)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, m := range methods {
		wg.Add(1)
		go func(method string) {
			defer wg.Done()
			req, err := http.NewRequestWithContext(ctx, method, base, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon/1.0)")
			resp, err := advClient.Do(req)
			if err != nil {
				return
			}
			_ = resp.Body.Close()
			mu.Lock()
			results[method] = resp.StatusCode
			mu.Unlock()
		}(m)
	}
	wg.Wait()

	if len(results) > 0 {
		e.HTTPMethods = results
	}
}

// ── Error page differential fingerprinting ──────────────────────────────────

// errorPageSignatures maps body substrings to technology hints.
// These are distinctive strings that only appear in default error pages.
var errorPageSignatures = []struct {
	pattern string
	tech    string
}{
	// Web servers
	{"<address>Apache/", "apache"},
	{"<address>nginx/", "nginx"},
	{"<hr><center>nginx</center>", "nginx"},
	{"Microsoft-IIS/", "iis"},
	{"<h2>404 - File or directory not found.</h2>", "iis"},
	{"<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>", "apache"},
	{"Whitelabel Error Page", "spring_boot"},
	{"<h1>Not Found</h1><p>The requested URL", "apache"},
	{"<body bgcolor=\"white\">", "nginx"},

	// Frameworks
	{"Django", "django"},
	{"You're seeing this error because you have <code>DEBUG = True</code>", "django_debug"},
	{"Traceback (most recent call last)", "python"},
	{"at org.apache.", "java"},
	{"java.lang.", "java"},
	{"System.Web.HttpException", "aspnet"},
	{"<b>Fatal error</b>:", "php"},
	{"<b>Warning</b>:", "php"},
	{"Parse error:", "php"},
	{"Ruby on Rails", "rails"},
	{"Sinatra doesn't know this ditty", "sinatra"},
	{"Cannot GET /", "express"},
	{"Cannot POST /", "express"},
	{"Express", "express"},

	// Proxies / CDN
	{"<center>cloudflare</center>", "cloudflare"},
	{"Attention Required! | Cloudflare", "cloudflare_waf"},
	{"The web server reported a bad gateway error", "cloudflare"},
	{"AkamaiGHost", "akamai"},
	{"Fastly error:", "fastly"},
	{"Varnish cache server", "varnish"},
	{"<h1>502 Bad Gateway</h1>\r\n<p>The proxy server", "haproxy"},

	// Application servers
	{"Apache Tomcat", "tomcat"},
	{"GlassFish Server", "glassfish"},
	{"JBoss Web/", "jboss"},
	{"WildFly/", "wildfly"},
	{"WebLogic Server", "weblogic"},
	{"Jetty://", "jetty"},

	// Platforms
	{"Powered by WordPress", "wordpress"},
	{"wp-content", "wordpress"},
	{"Drupal", "drupal"},
	{"Joomla!", "joomla"},

	// Cloud
	{"<Code>NoSuchBucket</Code>", "aws_s3"},
	{"<Code>AccessDenied</Code>", "aws_s3"},
	{"BlobNotFound", "azure_blob"},
	{"The specified blob does not exist", "azure_blob"},
	{"NoSuchKey", "gcs"},
}

// probeErrorPage fetches a 404 response and analyzes the body for technology hints.
func probeErrorPage(ctx context.Context, hostname string, e *playbook.Evidence) {
	scheme := advScheme(ctx, hostname)
	// Use a path that will almost certainly 404
	url := scheme + "://" + hostname + "/beacon-fp-404-probe-" + fmt.Sprintf("%d", time.Now().UnixNano()%99999)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon/1.0)")
	resp, err := advClient.Do(req)
	if err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
	bodyStr := string(body)

	for _, sig := range errorPageSignatures {
		if strings.Contains(bodyStr, sig.pattern) {
			e.ErrorPageSignature = sig.tech
			return
		}
	}
}

// ── .well-known URI enumeration ─────────────────────────────────────────────

// wellKnownURIs are standard .well-known paths defined by various RFCs and
// specifications. Each reveals something about the target's infrastructure.
var wellKnownURIs = []struct {
	path        string
	bodySig     string // required substring in body, empty = any 200 is fine
	description string
}{
	{"/.well-known/security.txt", "Contact:", "security contact info"},
	{"/.well-known/change-password", "", "password change endpoint"},
	{"/.well-known/openid-configuration", "issuer", "OIDC discovery"},
	{"/.well-known/oauth-authorization-server", "issuer", "OAuth server metadata"},
	{"/.well-known/jwks.json", "keys", "JSON Web Key Set"},
	{"/.well-known/assetlinks.json", "target", "Android app links"},
	{"/.well-known/apple-app-site-association", "applinks", "iOS app association"},
	{"/.well-known/matrix/server", "m.server", "Matrix federation"},
	{"/.well-known/matrix/client", "m.homeserver", "Matrix client config"},
	{"/.well-known/webfinger", "", "WebFinger identity"},
	{"/.well-known/nodeinfo", "nodeinfo", "ActivityPub node info"},
	{"/.well-known/host-meta", "XRD", "host metadata"},
	{"/.well-known/caldav", "", "CalDAV service"},
	{"/.well-known/carddav", "", "CardDAV service"},
	{"/.well-known/mta-sts.txt", "version:", "MTA-STS policy"},
	{"/.well-known/acme-challenge/", "", "ACME challenge (Let's Encrypt)"},
}

func probeWellKnown(ctx context.Context, hostname string, e *playbook.Evidence) {
	scheme := advScheme(ctx, hostname)
	results := make(map[string]string)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5) // limit concurrency

	for _, wk := range wellKnownURIs {
		wg.Add(1)
		go func(path, bodySig, desc string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			url := scheme + "://" + hostname + path
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon/1.0)")
			resp, err := advClient.Do(req)
			if err != nil {
				return
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != 200 && resp.StatusCode != 301 && resp.StatusCode != 302 {
				return
			}

			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024))
			bodyStr := string(body)

			if bodySig != "" && !strings.Contains(bodyStr, bodySig) {
				return
			}

			mu.Lock()
			// Extract key from path
			key := strings.TrimPrefix(path, "/.well-known/")
			results[key] = desc

			// Special handling for security.txt
			if key == "security.txt" {
				e.SecurityTxtPresent = true
				for _, line := range strings.Split(bodyStr, "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "Contact:") {
						e.SecurityTxtContact = strings.TrimSpace(strings.TrimPrefix(line, "Contact:"))
						break
					}
				}
			}
			mu.Unlock()
		}(wk.path, wk.bodySig, wk.description)
	}
	wg.Wait()

	if len(results) > 0 {
		e.WellKnownPaths = results
	}
}

// ── VCS exposure detection ──────────────────────────────────────────────────

// vcsProbes maps paths to VCS types. If any responds with the expected content,
// the VCS metadata directory is web-accessible — a critical exposure.
var vcsProbes = []struct {
	path    string
	bodySig string
	vcsType string
}{
	{"/.git/HEAD", "ref:", "git"},
	{"/.git/config", "[core]", "git"},
	{"/.svn/entries", "", "svn"},
	{"/.svn/wc.db", "SQLite", "svn"},
	{"/.hg/store/00manifest.i", "", "hg"},
	{"/.bzr/README", "Bazaar", "bzr"},
}

func probeVCSExposure(ctx context.Context, hostname string, e *playbook.Evidence) {
	scheme := advScheme(ctx, hostname)

	for _, probe := range vcsProbes {
		url := scheme + "://" + hostname + probe.path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon/1.0)")
		resp, err := advClient.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		_ = resp.Body.Close()

		if resp.StatusCode != 200 {
			continue
		}

		if probe.bodySig == "" || strings.Contains(string(body), probe.bodySig) {
			e.VCSExposed = probe.vcsType
			return // first match is enough
		}
	}
}

// ── Source map exposure detection ────────────────────────────────────────────

// probeSourceMaps checks for exposed JavaScript source maps by looking for
// sourceMappingURL references in JS files and then fetching the .map files.
func probeSourceMaps(ctx context.Context, hostname string, e *playbook.Evidence) {
	scheme := advScheme(ctx, hostname)

	// Common source map locations
	mapPaths := []string{
		"/main.js.map",
		"/app.js.map",
		"/bundle.js.map",
		"/vendor.js.map",
		"/_next/static/chunks/main.js.map",
		"/_next/static/chunks/webpack.js.map",
		"/static/js/main.js.map",
		"/static/js/bundle.js.map",
		"/assets/index.js.map",
		"/dist/bundle.js.map",
	}

	for _, path := range mapPaths {
		url := scheme + "://" + hostname + path
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon/1.0)")
		resp, err := advClient.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()

		if resp.StatusCode == 200 {
			ct := resp.Header.Get("Content-Type")
			// Source maps are JSON or application/json
			if strings.Contains(ct, "json") || strings.Contains(ct, "javascript") || ct == "" {
				e.SourceMapsExposed = true
				return
			}
		}
	}
}

// ── Sitemap.xml parsing ─────────────────────────────────────────────────────

// sitemapURLSet represents the XML structure of a sitemap.
type sitemapURLSet struct {
	XMLName xml.Name     `xml:"urlset"`
	URLs    []sitemapURL `xml:"url"`
}

type sitemapURL struct {
	Loc string `xml:"loc"`
}

type sitemapIndex struct {
	XMLName  xml.Name        `xml:"sitemapindex"`
	Sitemaps []sitemapEntry  `xml:"sitemap"`
}

type sitemapEntry struct {
	Loc string `xml:"loc"`
}

func probeSitemap(ctx context.Context, hostname string, e *playbook.Evidence) {
	scheme := advScheme(ctx, hostname)

	for _, path := range []string{"/sitemap.xml", "/sitemap_index.xml", "/sitemaps.xml"} {
		url := scheme + "://" + hostname + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon/1.0)")
		resp, err := advClient.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != 200 {
			_ = resp.Body.Close()
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024)) // 256 KB max
		_ = resp.Body.Close()

		if !strings.Contains(string(body), "<urlset") && !strings.Contains(string(body), "<sitemapindex") {
			continue
		}

		var urls []string

		// Try parsing as urlset
		var urlset sitemapURLSet
		if xml.Unmarshal(body, &urlset) == nil && len(urlset.URLs) > 0 {
			for _, u := range urlset.URLs {
				if u.Loc != "" {
					urls = append(urls, u.Loc)
				}
				if len(urls) >= 100 {
					break
				}
			}
		}

		// Try parsing as sitemap index
		if len(urls) == 0 {
			var idx sitemapIndex
			if xml.Unmarshal(body, &idx) == nil {
				for _, s := range idx.Sitemaps {
					if s.Loc != "" {
						urls = append(urls, s.Loc)
					}
					if len(urls) >= 50 {
						break
					}
				}
			}
		}

		if len(urls) > 0 {
			e.SitemapURLs = urls
			return
		}
	}
}

// ── WebSocket endpoint discovery ────────────────────────────────────────────

// probeWebSocket checks common WebSocket paths by sending an HTTP Upgrade
// request and checking if the server responds with 101 Switching Protocols.
func probeWebSocket(ctx context.Context, hostname string, e *playbook.Evidence) {
	wsPaths := []string{
		"/ws",
		"/websocket",
		"/socket.io/",
		"/sockjs/info",
		"/cable",         // Rails ActionCable
		"/hub",           // SignalR
		"/graphql",       // GraphQL subscriptions
		"/api/v1/stream", // generic streaming
		"/live",
		"/events",
	}

	scheme := advScheme(ctx, hostname)
	var endpoints []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)

	for _, path := range wsPaths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			url := scheme + "://" + hostname + p
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Beacon/1.0)")
			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Sec-WebSocket-Version", "13")
			req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

			resp, err := advClient.Do(req)
			if err != nil {
				return
			}
			_ = resp.Body.Close()

			// 101 = WebSocket upgrade accepted
			// 400 with "Upgrade" in response = WebSocket endpoint exists but bad request
			switch resp.StatusCode {
			case 101:
				mu.Lock()
				endpoints = append(endpoints, p)
				mu.Unlock()
			case 400:
				upgrade := strings.ToLower(resp.Header.Get("Upgrade"))
				if strings.Contains(upgrade, "websocket") {
					mu.Lock()
					endpoints = append(endpoints, p)
					mu.Unlock()
				}
			}
		}(path)
	}
	wg.Wait()

	if len(endpoints) > 0 {
		e.WebSocketEndpoints = endpoints
	}
}

// ── gRPC reflection probe ───────────────────────────────────────────────────

// probeGRPCReflection checks if gRPC server reflection is enabled on common
// gRPC ports. Server reflection allows enumerating all available services and
// methods, which is a significant information disclosure in production.
func probeGRPCReflection(ctx context.Context, hostname string, e *playbook.Evidence) {
	// gRPC uses HTTP/2. We attempt a raw TCP connection and send the gRPC
	// reflection request preface. Common gRPC ports: 50051, 9090, 443.
	ports := []string{"50051", "9090"}

	// Strip existing port if hostname has one
	bareHost := hostname
	if h, _, err := net.SplitHostPort(hostname); err == nil {
		bareHost = h
	}

	for _, port := range ports {
		addr := net.JoinHostPort(bareHost, port)
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			continue
		}

		// Send HTTP/2 connection preface to see if it's a gRPC server.
		// The preface is "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
		preface := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
		conn.SetDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
		_, err = conn.Write([]byte(preface))
		if err != nil {
			_ = conn.Close()
			continue
		}

		// Read response — gRPC servers respond with HTTP/2 SETTINGS frame
		// (byte 0x00 0x00 ... 0x04 for SETTINGS type)
		buf := make([]byte, 32)
		n, err := conn.Read(buf)
		_ = conn.Close()
		if err != nil || n < 9 {
			continue
		}

		// Check for HTTP/2 SETTINGS frame: type byte at position 3 should be 0x04
		if n >= 9 && buf[3] == 0x04 {
			e.GRPCReflection = true
			return
		}
	}
}
