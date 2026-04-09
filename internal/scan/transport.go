package scan

import (
	"crypto/tls"
	"net/http"
	"sync"
	"time"
)

var (
	sharedTransportOnce sync.Once
	sharedTransport     *http.Transport
)

// SharedTransport returns a pre-configured http.Transport with connection
// pooling enabled. All scanners sharing this transport reuse TCP connections
// via HTTP keep-alive, eliminating redundant TCP+TLS handshakes.
//
// The returned transport is a singleton — safe for concurrent use by multiple
// goroutines and multiple http.Client instances.
func SharedTransport() *http.Transport {
	sharedTransportOnce.Do(func() {
		sharedTransport = &http.Transport{
			DialContext:         CachedDialContext(), // DNS cache: deduplicate lookups across scanners
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20, // multiple scanners hit same host
			IdleConnTimeout:     90 * time.Second,
			TLSClientConfig:    &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // security scanner targets arbitrary hosts
			DisableCompression:  false,
			ForceAttemptHTTP2:   true,
		}
	})
	return sharedTransport
}

// SharedClient returns an http.Client using the shared transport with
// the given timeout. CheckRedirect is set to not follow redirects so
// scanners can inspect redirect responses directly.
func SharedClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: SharedTransport(),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
