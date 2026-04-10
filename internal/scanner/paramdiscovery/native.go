package paramdiscovery

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// DiscoveredParam represents a parameter found via response differential
// analysis (the same technique as Arjun, reimplemented in native Go).
type DiscoveredParam struct {
	Name     string // parameter name
	Method   string // GET or POST
	Evidence string // what changed in the response
}

// baseline captures the characteristics of a response for comparison.
type baseline struct {
	status     int
	bodyLen    int
	bodyHash   string
	headerKeys []string
}

// DiscoverParams brute-forces parameter names on an endpoint by comparing
// response characteristics (status, body length, body hash, headers) with
// and without params. Uses batching and binary search for efficiency.
//
// This is a Deep-mode operation: it sends many probing requests to the target.
func DiscoverParams(ctx context.Context, client *http.Client, targetURL string, method string) []DiscoveredParam {
	if method == "" {
		method = "GET"
	}
	method = strings.ToUpper(method)

	// Get baseline response.
	bl := getBaseline(ctx, client, targetURL, method)
	if bl == nil {
		return nil
	}

	// Batch parameters for efficiency: send batchSize at once. If the
	// response differs from baseline, binary-search to isolate which
	// params caused the change.
	const batchSize = 10
	var discovered []DiscoveredParam

	for i := 0; i < len(commonParams); i += batchSize {
		if ctx.Err() != nil {
			break
		}

		end := i + batchSize
		if end > len(commonParams) {
			end = len(commonParams)
		}
		batch := commonParams[i:end]

		diff := probeParams(ctx, client, targetURL, method, batch, bl)
		if diff == "" {
			continue // no change — none of these params matter
		}

		// Binary search: narrow down which param(s) in the batch caused change.
		found := binarySearchParams(ctx, client, targetURL, method, batch, bl)
		discovered = append(discovered, found...)
	}

	return discovered
}

// getBaseline sends a request with no extra params and captures response characteristics.
func getBaseline(ctx context.Context, client *http.Client, targetURL string, method string) *baseline {
	// Send two baseline requests to account for dynamic content.
	bl1 := sendProbe(ctx, client, targetURL, method, nil)
	if bl1 == nil {
		return nil
	}
	bl2 := sendProbe(ctx, client, targetURL, method, nil)
	if bl2 == nil {
		return bl1
	}

	// If responses differ significantly even without params, the endpoint
	// is too dynamic for differential analysis.
	if bl1.status != bl2.status {
		return nil // status changes without params — too noisy
	}
	lenDiff := abs(bl1.bodyLen - bl2.bodyLen)
	if bl1.bodyLen > 0 && float64(lenDiff)/float64(bl1.bodyLen) > 0.1 {
		return nil // body length varies >10% between identical requests — too noisy
	}

	return bl1
}

// probeParams sends a request with the given params set to random values and
// returns a description of what changed, or "" if nothing changed.
func probeParams(ctx context.Context, client *http.Client, targetURL string, method string, params []string, bl *baseline) string {
	resp := sendProbe(ctx, client, targetURL, method, params)
	if resp == nil {
		return ""
	}
	return diffBaseline(bl, resp)
}

// diffBaseline compares a probe response against the baseline and returns
// a description of what changed.
func diffBaseline(bl, probe *baseline) string {
	var diffs []string

	if bl.status != probe.status {
		diffs = append(diffs, fmt.Sprintf("status changed: %d -> %d", bl.status, probe.status))
	}

	if bl.bodyLen > 0 {
		lenDiff := abs(bl.bodyLen - probe.bodyLen)
		pct := float64(lenDiff) / float64(bl.bodyLen) * 100
		if pct > 10 {
			diffs = append(diffs, fmt.Sprintf("body length changed: %d -> %d (%.0f%%)", bl.bodyLen, probe.bodyLen, pct))
		}
	} else if probe.bodyLen > 100 {
		diffs = append(diffs, fmt.Sprintf("body appeared: 0 -> %d bytes", probe.bodyLen))
	}

	if bl.bodyHash != probe.bodyHash && bl.bodyLen == probe.bodyLen {
		diffs = append(diffs, "body content changed (same length)")
	}

	// Check for new headers.
	blHeaders := make(map[string]bool, len(bl.headerKeys))
	for _, h := range bl.headerKeys {
		blHeaders[h] = true
	}
	for _, h := range probe.headerKeys {
		if !blHeaders[h] {
			diffs = append(diffs, fmt.Sprintf("new header: %s", h))
		}
	}

	if len(diffs) == 0 {
		return ""
	}
	return strings.Join(diffs, "; ")
}

// sendProbe sends a single request with optional params and captures
// response characteristics.
func sendProbe(ctx context.Context, client *http.Client, targetURL string, method string, params []string) *baseline {
	// Build param values — use a consistent random-looking value per param.
	paramMap := make(map[string]string, len(params))
	for _, p := range params {
		paramMap[p] = randomValue()
	}

	var req *http.Request
	var err error

	switch method {
	case "GET":
		u, parseErr := url.Parse(targetURL)
		if parseErr != nil {
			return nil
		}
		q := u.Query()
		for k, v := range paramMap {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
		req, err = http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	case "POST":
		form := url.Values{}
		for k, v := range paramMap {
			form.Set(k, v)
		}
		req, err = http.NewRequestWithContext(ctx, "POST", targetURL, strings.NewReader(form.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	default:
		return nil
	}

	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BeaconScanner)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024)) // 1MB max

	hash := sha256.Sum256(body)

	var headerKeys []string
	for k := range resp.Header {
		headerKeys = append(headerKeys, strings.ToLower(k))
	}
	sort.Strings(headerKeys)

	return &baseline{
		status:     resp.StatusCode,
		bodyLen:    len(body),
		bodyHash:   fmt.Sprintf("%x", hash[:8]),
		headerKeys: headerKeys,
	}
}

// binarySearchParams narrows down a batch of params to find the ones that
// cause a response change.
func binarySearchParams(ctx context.Context, client *http.Client, targetURL string, method string, params []string, bl *baseline) []DiscoveredParam {
	if ctx.Err() != nil {
		return nil
	}

	if len(params) == 0 {
		return nil
	}

	if len(params) == 1 {
		diff := probeParams(ctx, client, targetURL, method, params, bl)
		if diff != "" {
			return []DiscoveredParam{{
				Name:     params[0],
				Method:   method,
				Evidence: diff,
			}}
		}
		return nil
	}

	// Split in half and test each half.
	mid := len(params) / 2
	left := params[:mid]
	right := params[mid:]

	var found []DiscoveredParam

	if diff := probeParams(ctx, client, targetURL, method, left, bl); diff != "" {
		found = append(found, binarySearchParams(ctx, client, targetURL, method, left, bl)...)
	}

	if diff := probeParams(ctx, client, targetURL, method, right, bl); diff != "" {
		found = append(found, binarySearchParams(ctx, client, targetURL, method, right, bl)...)
	}

	return found
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// randomValue generates a short random string for parameter probing. Uses a
// deterministic source seeded per-call so values vary between requests but
// are not cryptographically unpredictable (not needed here).
func randomValue() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano())) // #nosec G404 -- probe values, not crypto
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	for i := range b {
		b[i] = charset[r.Intn(len(charset))]
	}
	return string(b)
}

// commonParams is a built-in wordlist of 500+ parameter names commonly found
// in web applications. Sourced from Arjun's wordlist, OWASP, and real-world
// API testing experience.
var commonParams = []string{
	// Authentication & identity
	"id", "uid", "user_id", "userid", "account_id", "accountid",
	"username", "user", "login", "email", "mail", "phone",
	"password", "passwd", "pass", "pwd", "secret",
	"token", "auth_token", "access_token", "refresh_token", "session",
	"api_key", "apikey", "api-key", "key", "app_key", "appkey",
	"client_id", "client_secret", "oauth_token",

	// CSRF / security
	"csrf", "csrf_token", "csrftoken", "_token", "authenticity_token",
	"nonce", "state", "xsrf", "xsrf_token",

	// Pagination & sorting
	"page", "p", "pg", "page_num", "pagenum", "pagenumber",
	"limit", "per_page", "perpage", "pagesize", "page_size", "count", "size",
	"offset", "skip", "start", "from", "cursor", "after", "before",
	"sort", "sortby", "sort_by", "order", "orderby", "order_by",
	"asc", "desc", "dir", "direction",

	// Search & filtering
	"q", "query", "search", "keyword", "keywords", "term", "terms",
	"filter", "filters", "where", "find",
	"name", "title", "label", "tag", "tags", "category", "categories",
	"type", "kind", "group", "class",
	"status", "state", "active", "enabled", "disabled", "deleted",
	"date", "from_date", "to_date", "start_date", "end_date",
	"created", "updated", "modified", "since", "until",
	"min", "max", "min_price", "max_price", "price",
	"year", "month", "day",

	// Content & resources
	"file", "filename", "path", "filepath", "dir", "directory", "folder",
	"url", "uri", "link", "href", "src", "source", "dest", "destination",
	"image", "img", "photo", "avatar", "icon", "logo",
	"content", "body", "text", "message", "msg", "comment", "note", "notes",
	"description", "desc", "summary", "abstract", "excerpt",
	"data", "payload", "json", "xml", "html", "raw",

	// Actions & callbacks
	"action", "method", "op", "operation", "command", "cmd",
	"callback", "cb", "redirect", "redirect_uri", "redirect_url",
	"return", "return_url", "returnurl", "return_to", "returnto",
	"next", "next_url", "continue", "continue_url", "goto", "target",
	"ref", "referer", "referrer", "origin",

	// Format & output
	"format", "fmt", "output", "response_type", "accept",
	"lang", "language", "locale", "l10n", "i18n",
	"encoding", "charset", "content_type", "mime",
	"pretty", "indent", "minify", "compress",
	"fields", "select", "include", "exclude", "expand", "embed",
	"verbose", "v", "detail", "details", "full",

	// Geographic & location
	"lat", "latitude", "lng", "longitude", "lon",
	"location", "address", "city", "zip", "zipcode", "postal",
	"country", "region", "province", "county",
	"geo", "coordinates", "coords",

	// Identifiers & references
	"uuid", "guid", "ref", "reference", "code", "hash",
	"slug", "handle", "alias", "sku", "upc", "ean",
	"product_id", "productid", "item_id", "itemid", "order_id", "orderid",
	"invoice_id", "transaction_id", "payment_id",

	// Boolean flags
	"debug", "test", "testing", "dev", "development", "staging",
	"admin", "is_admin", "isadmin", "superuser",
	"preview", "draft", "publish", "published",
	"verify", "validate", "confirmed", "approved",
	"force", "override", "bypass", "skip_validation",

	// API versioning
	"version", "v", "ver", "api_version",

	// Rate limiting / analytics
	"rate", "throttle", "timeout", "wait", "delay", "retry",
	"track", "tracking", "analytics", "utm_source", "utm_medium", "utm_campaign",

	// Database / backend
	"table", "collection", "database", "db", "schema",
	"column", "field", "attribute", "property", "prop",
	"index", "idx",
	"join", "relationship", "relation", "association",
	"populate", "with", "load", "fetch",

	// Template / rendering
	"template", "layout", "theme", "skin", "style",
	"view", "render", "component", "widget", "partial",
	"mode", "display", "show", "hide",

	// File operations
	"upload", "download", "export", "import",
	"attachment", "attachments", "document", "documents",
	"media", "resource", "resources", "asset", "assets",

	// Network / proxy
	"host", "hostname", "domain", "subdomain", "port",
	"ip", "ip_address", "server", "proxy", "gateway",
	"protocol", "scheme", "ssl", "tls", "https",

	// Headers / metadata
	"header", "headers", "cookie", "cookies",
	"user_agent", "useragent", "ua",
	"x_forwarded_for", "x_real_ip", "x_custom_header",

	// Error handling
	"error", "err", "errors", "exception", "warning",
	"stacktrace", "trace", "backtrace",

	// Config / settings
	"config", "configuration", "settings", "preferences", "prefs",
	"option", "options", "param", "params", "parameter", "parameters",
	"env", "environment",

	// Webhook / event
	"event", "events", "hook", "webhook", "trigger",
	"channel", "topic", "queue", "stream",
	"subscribe", "unsubscribe", "publish",

	// Misc common
	"value", "val", "amount", "quantity", "qty",
	"width", "height", "length", "weight",
	"color", "colour", "size", "dimension",
	"role", "roles", "permission", "permissions", "scope", "scopes",
	"grant", "grant_type", "response_mode",

	// Security testing (may trigger WAF/error pages)
	"exec", "execute", "eval", "system", "shell",
	"include", "require", "load", "read", "write",
	"delete", "remove", "drop", "truncate", "update", "insert",
	"select", "union", "join", "where", "having", "group_by",

	// SSRF / path traversal testing
	"url", "uri", "path", "file", "filename",
	"document", "page", "folder", "root",
	"site", "website", "domain", "host",

	// Common framework params
	"_method", "_format", "_locale",
	"utf8", "commit", "authenticity_token",
	"__RequestVerificationToken",
	"X-Requested-With", "X-CSRF-TOKEN",

	// GraphQL
	"query", "variables", "operationName", "extensions",

	// JSON-specific
	"ids", "items", "objects", "records", "results",
	"total", "count", "length", "metadata", "meta",
	"pagination", "paging", "links", "href",

	// Cloud / S3
	"bucket", "prefix", "marker", "delimiter",
	"max_keys", "max-keys", "continuation_token",
	"region", "zone", "namespace",

	// Temporal
	"timestamp", "ts", "time", "datetime",
	"created_at", "updated_at", "deleted_at",
	"expires", "expires_at", "expiry", "ttl",

	// Contact / personal
	"first_name", "firstname", "last_name", "lastname",
	"full_name", "fullname", "display_name", "displayname",
	"company", "organization", "org",
	"street", "address1", "address2",
	"bio", "about", "profile",

	// E-commerce
	"price", "cost", "total", "subtotal", "tax", "discount",
	"coupon", "promo", "promo_code", "voucher",
	"currency", "payment_method", "card", "cvv",
	"shipping", "billing", "cart", "checkout",

	// Social / messaging
	"to", "from", "cc", "bcc", "subject",
	"recipient", "sender", "reply", "reply_to",
	"thread", "conversation", "room",
	"like", "share", "follow", "block", "mute",
}
