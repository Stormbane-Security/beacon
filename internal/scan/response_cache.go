package scan

import (
	"context"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// CachedResponse stores the relevant parts of an HTTP response so multiple
// scanners can inspect the same data without re-fetching.
type CachedResponse struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	Error      error
}

// ResponseCache stores HTTP responses that multiple scanners need.
// The first scanner to request a URL fetches it; subsequent scanners
// get the cached response. Thread-safe.
type ResponseCache struct {
	mu     sync.Mutex
	cache  map[string]*cacheEntry
	client *http.Client
}

// cacheEntry implements inline singleflight: the first goroutine to create
// the entry starts the fetch and closes done; all others block on done.
type cacheEntry struct {
	done   chan struct{}
	result *CachedResponse
}

// NewResponseCache creates a ResponseCache backed by the given HTTP client.
func NewResponseCache(client *http.Client) *ResponseCache {
	return &ResponseCache{
		cache:  make(map[string]*cacheEntry),
		client: client,
	}
}

// Get fetches the URL, caching the result. Concurrent calls for the
// same URL block until the first fetch completes (singleflight pattern).
func (rc *ResponseCache) Get(ctx context.Context, url string) *CachedResponse {
	return rc.GetWithHeaders(ctx, url, nil)
}

// GetWithHeaders fetches with custom headers (separate cache key).
// The cache key includes sorted header key=value pairs so different header
// combinations are cached independently.
func (rc *ResponseCache) GetWithHeaders(ctx context.Context, url string, headers map[string]string) *CachedResponse {
	key := cacheKey(url, headers)

	rc.mu.Lock()
	if e, ok := rc.cache[key]; ok {
		rc.mu.Unlock()
		// Wait for the in-flight fetch to finish.
		select {
		case <-e.done:
			return e.result
		case <-ctx.Done():
			return &CachedResponse{Error: ctx.Err()}
		}
	}
	// First caller — create entry and start fetch.
	e := &cacheEntry{done: make(chan struct{})}
	rc.cache[key] = e
	rc.mu.Unlock()

	e.result = rc.fetch(ctx, url, headers)
	close(e.done)
	return e.result
}

// fetch performs the actual HTTP request.
func (rc *ResponseCache) fetch(ctx context.Context, url string, headers map[string]string) *CachedResponse {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return &CachedResponse{Error: err}
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := rc.client.Do(req)
	if err != nil {
		return &CachedResponse{Error: err}
	}
	defer func() { _ = resp.Body.Close() }()

	// Cap body read at 2 MB to avoid memory issues on huge responses.
	const maxBody = 2 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return &CachedResponse{
			StatusCode: resp.StatusCode,
			Headers:    resp.Header,
			Error:      err,
		}
	}

	return &CachedResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       body,
	}
}

// cacheKey builds a deterministic key from the URL and optional headers.
func cacheKey(url string, headers map[string]string) string {
	if len(headers) == 0 {
		return url
	}
	// Sort header keys for deterministic ordering.
	pairs := make([]string, 0, len(headers))
	for k, v := range headers {
		pairs = append(pairs, k+"="+v)
	}
	sort.Strings(pairs)
	return url + "\x00" + strings.Join(pairs, "\x00")
}
