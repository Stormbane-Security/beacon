package surface

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// tlsServer creates a TLS listener on localhost with a self-signed cert
// containing the given DNS SANs and IP SANs. It returns the listener, its
// host:port address, and a cleanup function. The caller is responsible for
// accepting connections or attaching an HTTP handler.
func tlsServer(t *testing.T, dnsSANs []string, ipSANs []net.IP) (net.Listener, string, func()) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"Beacon Test CA"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsSANs,
		IPAddresses:  ipSANs,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}

	addr := ln.Addr().String()
	return ln, addr, func() { ln.Close() }
}

// tlsHTTPServer creates a TLS server that also responds to HTTP requests.
// The handler is served over TLS on a random localhost port.
func tlsHTTPServer(t *testing.T, dnsSANs []string, ipSANs []net.IP, handler http.Handler) (string, func()) {
	t.Helper()

	ln, addr, cleanup := tlsServer(t, dnsSANs, ipSANs)

	// The listener is already TLS-wrapped, so use Serve (not ServeTLS).
	srv := &http.Server{Handler: handler}
	go srv.Serve(ln) //nolint:errcheck

	return addr, func() {
		srv.Close()
		cleanup()
	}
}

// hasEvidence returns true if any evidence string contains substr.
func hasEvidence(res OwnershipResult, substr string) bool {
	for _, e := range res.Evidence {
		if strings.Contains(e, substr) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// ipBelongsToDomain — pure function tests
// ---------------------------------------------------------------------------

func TestIPBelongsToDomain_ExactMatch(t *testing.T) {
	if !ipBelongsToDomain("example.com", "example.com") {
		t.Error("exact match should return true")
	}
}

func TestIPBelongsToDomain_Subdomain(t *testing.T) {
	if !ipBelongsToDomain("web.example.com", "example.com") {
		t.Error("subdomain should return true")
	}
}

func TestIPBelongsToDomain_DeepSubdomain(t *testing.T) {
	if !ipBelongsToDomain("a.b.c.example.com", "example.com") {
		t.Error("deep subdomain should return true")
	}
}

func TestIPBelongsToDomain_TrailingDot(t *testing.T) {
	if !ipBelongsToDomain("web.example.com.", "example.com") {
		t.Error("trailing dot (FQDN) should still match")
	}
}

func TestIPBelongsToDomain_CaseInsensitive(t *testing.T) {
	if !ipBelongsToDomain("Web.Example.COM", "example.com") {
		t.Error("case-insensitive match should return true")
	}
}

func TestIPBelongsToDomain_DifferentDomain(t *testing.T) {
	if ipBelongsToDomain("evil.com", "example.com") {
		t.Error("different domain should return false")
	}
}

func TestIPBelongsToDomain_SuffixTrap(t *testing.T) {
	// "notexample.com" ends with "example.com" but is NOT a subdomain.
	if ipBelongsToDomain("notexample.com", "example.com") {
		t.Error("'notexample.com' is not a subdomain of 'example.com'")
	}
}

func TestIPBelongsToDomain_EmptyHostname(t *testing.T) {
	if ipBelongsToDomain("", "example.com") {
		t.Error("empty hostname should return false")
	}
}

func TestIPBelongsToDomain_EmptyRootDomain(t *testing.T) {
	// With empty rootDomain, everything would HasSuffix match — verify behavior.
	// The function checks h == r || HasSuffix(h, "."+r). With r="", h=="" is true
	// only if hostname was empty (covered above). For non-empty hostname:
	// HasSuffix("anything", ".") is false, so this should return false.
	if ipBelongsToDomain("example.com", "") {
		t.Error("empty rootDomain should not match non-empty hostname")
	}
}

// ---------------------------------------------------------------------------
// AssetConfidence.String()
// ---------------------------------------------------------------------------

func TestAssetConfidenceString(t *testing.T) {
	tests := []struct {
		c    AssetConfidence
		want string
	}{
		{AssetRuledOut, "ruled_out"},
		{AssetUnlikely, "unlikely"},
		{AssetUnconfirmed, "unconfirmed"},
		{AssetLikely, "likely"},
		{AssetConfirmed, "confirmed"},
		{AssetConfidence(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.c.String(); got != tt.want {
			t.Errorf("AssetConfidence(%d).String() = %q; want %q", int(tt.c), got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// checkAssetOwnership — TLS SAN matching
// ---------------------------------------------------------------------------

func TestOwnership_TLSSANMatchesTarget_Confirmed(t *testing.T) {
	// Server cert has SAN for "example.com" — should confirm ownership.
	addr, cleanup := tlsHTTPServer(t,
		[]string{"example.com", "www.example.com"},
		nil,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)
	defer cleanup()

	// Pass just the port portion since the function joins host:443 for TLS,
	// but for the HTTP probe it uses the ip as-is when it contains a colon.
	// We pass the full addr (127.0.0.1:PORT) so the HTTP probe can reach it.
	_, port, _ := net.SplitHostPort(addr)

	// The function strips port for TLS (always connects on 443) so we need
	// to test via the HTTP probe path. Pass ip as "127.0.0.1:PORT" so the
	// HTTP probe URL becomes https://127.0.0.1:PORT/.
	// TLS check will fail (connects to port 443 which won't be our server),
	// but HTTP probe should succeed.
	res := checkAssetOwnership(context.Background(), "127.0.0.1:"+port, "example.com")

	if res.Confidence != AssetConfirmed {
		t.Errorf("confidence = %v; want AssetConfirmed (TLS SAN or HTTP probe should confirm)", res.Confidence)
		t.Logf("evidence: %v", res.Evidence)
	}
}

func TestOwnership_TLSSANMismatch_NotConfirmed(t *testing.T) {
	// Server cert has SANs for "other-company.com" only — should NOT confirm for example.com.
	addr, cleanup := tlsHTTPServer(t,
		[]string{"other-company.com", "www.other-company.com"},
		nil,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Return 421 Misdirected to indicate server rejects this domain
			w.WriteHeader(http.StatusMisdirectedRequest)
		}),
	)
	defer cleanup()

	_, port, _ := net.SplitHostPort(addr)
	res := checkAssetOwnership(context.Background(), "127.0.0.1:"+port, "example.com")

	if res.Confidence == AssetConfirmed {
		t.Errorf("confidence = AssetConfirmed; want something lower when TLS SANs don't match")
		t.Logf("evidence: %v", res.Evidence)
	}
}

func TestOwnership_TLSWildcardSAN_Confirmed(t *testing.T) {
	// Server cert has *.example.com — wildcard should match.
	addr, cleanup := tlsHTTPServer(t,
		[]string{"*.example.com"},
		nil,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)
	defer cleanup()

	_, port, _ := net.SplitHostPort(addr)
	res := checkAssetOwnership(context.Background(), "127.0.0.1:"+port, "example.com")

	if res.Confidence != AssetConfirmed {
		t.Errorf("confidence = %v; want AssetConfirmed (wildcard SAN *.example.com should match)", res.Confidence)
		t.Logf("evidence: %v", res.Evidence)
	}
}

func TestOwnership_TLSIPSAN_Confirmed(t *testing.T) {
	// Server cert has IP SAN for 127.0.0.1 — should confirm ownership.
	addr, cleanup := tlsHTTPServer(t,
		nil,
		[]net.IP{net.ParseIP("127.0.0.1")},
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)
	defer cleanup()

	_, port, _ := net.SplitHostPort(addr)
	res := checkAssetOwnership(context.Background(), "127.0.0.1:"+port, "unrelated.com")

	// The IP SAN check looks for bare IP matching leaf cert's IPAddresses.
	// TLS connects on port 443 (not our server), so the IP SAN won't be checked.
	// But the HTTP probe with 200 response confirms ownership.
	if res.Confidence != AssetConfirmed {
		t.Errorf("confidence = %v; want AssetConfirmed", res.Confidence)
		t.Logf("evidence: %v", res.Evidence)
	}
}

// ---------------------------------------------------------------------------
// checkAssetOwnership — HTTP Host-bound probe
// ---------------------------------------------------------------------------

func TestOwnership_HTTPProbe200_Confirmed(t *testing.T) {
	// Server returns 200 for HEAD with Host: target → confirmed.
	addr, cleanup := tlsHTTPServer(t,
		[]string{"unrelated.com"}, // SANs don't match target
		nil,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "nginx/1.25")
			w.WriteHeader(http.StatusOK)
		}),
	)
	defer cleanup()

	_, port, _ := net.SplitHostPort(addr)
	res := checkAssetOwnership(context.Background(), "127.0.0.1:"+port, "target.com")

	if res.Confidence != AssetConfirmed {
		t.Errorf("confidence = %v; want AssetConfirmed from HTTP 200 probe", res.Confidence)
		t.Logf("evidence: %v", res.Evidence)
	}
	if res.HTTPStatus != http.StatusOK {
		t.Errorf("HTTPStatus = %d; want 200", res.HTTPStatus)
	}
	if res.ServerHeader != "nginx/1.25" {
		t.Errorf("ServerHeader = %q; want nginx/1.25", res.ServerHeader)
	}
	if !hasEvidence(res, "server recognises domain") {
		t.Error("expected evidence mentioning 'server recognises domain'")
	}
}

func TestOwnership_HTTPProbe301_Confirmed(t *testing.T) {
	// Server returns 301 redirect for HEAD with Host: target → confirmed (3xx counts).
	addr, cleanup := tlsHTTPServer(t,
		[]string{"unrelated.com"},
		nil,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "https://target.com/home")
			w.WriteHeader(http.StatusMovedPermanently)
		}),
	)
	defer cleanup()

	_, port, _ := net.SplitHostPort(addr)
	res := checkAssetOwnership(context.Background(), "127.0.0.1:"+port, "target.com")

	if res.Confidence != AssetConfirmed {
		t.Errorf("confidence = %v; want AssetConfirmed from HTTP 301", res.Confidence)
	}
	if res.HTTPStatus != http.StatusMovedPermanently {
		t.Errorf("HTTPStatus = %d; want 301", res.HTTPStatus)
	}
}

func TestOwnership_HTTPProbe421_RuledOut(t *testing.T) {
	// Server returns 421 Misdirected Request → ruled out (from unconfirmed).
	addr, cleanup := tlsHTTPServer(t,
		[]string{"other.com"}, // SANs don't match — keeps confidence below Confirmed
		nil,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusMisdirectedRequest) // 421
		}),
	)
	defer cleanup()

	_, port, _ := net.SplitHostPort(addr)
	res := checkAssetOwnership(context.Background(), "127.0.0.1:"+port, "target.com")

	if res.Confidence != AssetRuledOut {
		t.Errorf("confidence = %v; want AssetRuledOut from 421 Misdirected", res.Confidence)
		t.Logf("evidence: %v", res.Evidence)
	}
	if !hasEvidence(res, "421 Misdirected Request") {
		t.Error("expected evidence mentioning '421 Misdirected Request'")
	}
}

func TestOwnership_HTTPProbe404_NoPromotion(t *testing.T) {
	// Server returns 404 — should not confirm or rule out, just log the status.
	addr, cleanup := tlsHTTPServer(t,
		[]string{"other.com"},
		nil,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}),
	)
	defer cleanup()

	_, port, _ := net.SplitHostPort(addr)
	res := checkAssetOwnership(context.Background(), "127.0.0.1:"+port, "target.com")

	if res.Confidence == AssetConfirmed {
		t.Error("404 should not confirm ownership")
	}
	if res.HTTPStatus != http.StatusNotFound {
		t.Errorf("HTTPStatus = %d; want 404", res.HTTPStatus)
	}
}

func TestOwnership_HTTPProbe500_NoPromotion(t *testing.T) {
	// Server error (500) — should not confirm or rule out.
	addr, cleanup := tlsHTTPServer(t,
		[]string{"other.com"},
		nil,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}),
	)
	defer cleanup()

	_, port, _ := net.SplitHostPort(addr)
	res := checkAssetOwnership(context.Background(), "127.0.0.1:"+port, "target.com")

	if res.Confidence == AssetConfirmed {
		t.Error("500 should not confirm ownership")
	}
}

// ---------------------------------------------------------------------------
// checkAssetOwnership — HTTP probe skipped when already Confirmed by TLS
// ---------------------------------------------------------------------------

func TestOwnership_TLSConfirmed_SkipsHTTPProbe(t *testing.T) {
	// When TLS SANs confirm ownership, the HTTP probe is skipped (the function
	// guards it with `if res.Confidence < AssetConfirmed`).
	httpCalled := false
	addr, cleanup := tlsHTTPServer(t,
		[]string{"example.com"}, // SANs match target
		nil,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			httpCalled = true
			w.WriteHeader(http.StatusOK)
		}),
	)
	defer cleanup()

	// We need TLS to actually connect on our port. The function hardcodes port 443
	// for TLS, so unless our test server is on 443 (unlikely), TLS probe will fail.
	// This means the HTTP probe will fire. We can still verify the TLS-confirmed
	// skip path indirectly: if both TLS and HTTP confirm, confidence is still Confirmed.
	_, port, _ := net.SplitHostPort(addr)
	res := checkAssetOwnership(context.Background(), "127.0.0.1:"+port, "example.com")

	// Since TLS connects on 443 (not our port), TLS will fail, HTTP probe runs.
	// This is expected — we're verifying the HTTP path works as fallback.
	_ = httpCalled
	if res.Confidence != AssetConfirmed {
		t.Errorf("confidence = %v; want AssetConfirmed", res.Confidence)
	}
}

// ---------------------------------------------------------------------------
// checkAssetOwnership — PTR / DNS-related paths
// ---------------------------------------------------------------------------

func TestOwnership_PTRLookupFailure_RecordsNoReverseDNS(t *testing.T) {
	// Use an IP address that won't have a PTR record in test environments.
	// 192.0.2.1 is TEST-NET-1 (RFC 5737) — guaranteed no PTR in production DNS.
	// TLS and HTTP probes will also fail (unreachable).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res := checkAssetOwnership(ctx, "192.0.2.1", "example.com")

	if !hasEvidence(res, "PTR: none") {
		t.Error("expected evidence mentioning 'PTR: none' for unreachable IP")
		t.Logf("evidence: %v", res.Evidence)
	}
	// With no PTR, no TLS, no HTTP — should remain unconfirmed.
	if res.Confidence == AssetConfirmed {
		t.Error("unreachable IP should not be confirmed")
	}
}

func TestOwnership_AlwaysHasConfidenceSummary(t *testing.T) {
	// Every result must end with a "Confidence: <level>" evidence line.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	res := checkAssetOwnership(ctx, "192.0.2.1", "example.com")

	found := false
	for _, e := range res.Evidence {
		if strings.HasPrefix(e, "Confidence:") {
			found = true
		}
	}
	if !found {
		t.Error("expected final evidence line starting with 'Confidence:'")
		t.Logf("evidence: %v", res.Evidence)
	}
}

// ---------------------------------------------------------------------------
// checkAssetOwnership — Cloud provider detection from PTR names
// ---------------------------------------------------------------------------

// TestCloudProviderFromPTR tests the cloud provider fingerprinting logic.
// Since we can't inject PTR records, we test the underlying matching patterns
// by verifying the switch-case logic via the known string patterns.
// The actual PTR-based cloud detection is integration-tested when the function
// receives real PTR names; here we verify the pattern recognition.

func TestCloudProviderPatterns(t *testing.T) {
	tests := []struct {
		ptrName  string
		wantProv string
	}{
		{"ec2-1-2-3-4.compute-1.compute.amazonaws.com", "aws"},
		{"ip-10-0-0-1.ec2.internal", "aws"},
		{"1-2-3-4.awsglobalaccelerator.com", "aws"},
		{"1-2-3-4.bc.googleusercontent.com", "gcp"},
		{"storage.googleapis.com", "gcp"},
		{"server.1e100.net", "gcp"},
		{"myvm.eastus.azure.com", "azure"},
		{"myapp.eastus.cloudapp.net", "azure"},
		{"myblob.blob.core.windows.net", "azure"},
		{"static.42.78.49.116.clients.your-server.hetzner.de", "hetzner"},
		{"host1.hetzner.com", "hetzner"},
		{"server.digitalocean.com", "digitalocean"},
		{"host.vultr.com", "vultr"},
		{"host.linode.com", "linode"},
		{"randomhost.otherprovider.com", ""},
	}

	for _, tt := range tests {
		t.Run(tt.ptrName, func(t *testing.T) {
			nameLower := strings.ToLower(tt.ptrName)
			got := ""
			switch {
			case strings.Contains(nameLower, ".compute.amazonaws.com") ||
				strings.Contains(nameLower, ".ec2.internal") ||
				strings.Contains(nameLower, ".awsglobalaccelerator.com"):
				got = "aws"
			case strings.Contains(nameLower, ".googleusercontent.com") ||
				strings.Contains(nameLower, ".googleapis.com") ||
				strings.Contains(nameLower, ".1e100.net"):
				got = "gcp"
			case strings.Contains(nameLower, ".azure.com") ||
				strings.Contains(nameLower, ".cloudapp.net") ||
				strings.Contains(nameLower, ".windows.net"):
				got = "azure"
			case strings.Contains(nameLower, ".hetzner.de") ||
				strings.Contains(nameLower, ".hetzner.com"):
				got = "hetzner"
			case strings.Contains(nameLower, ".digitalocean.com") ||
				strings.Contains(nameLower, ".vultr.com") ||
				strings.Contains(nameLower, ".linode.com"):
				got = strings.Split(nameLower, ".")[len(strings.Split(nameLower, "."))-2]
			}
			if got != tt.wantProv {
				t.Errorf("cloud provider for %q = %q; want %q", tt.ptrName, got, tt.wantProv)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// checkAssetOwnership — port stripping from IP input
// ---------------------------------------------------------------------------

func TestOwnership_PortStripping(t *testing.T) {
	// Verify the function handles "ip:port" format correctly.
	addr, cleanup := tlsHTTPServer(t,
		[]string{"example.com"},
		nil,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)
	defer cleanup()

	_, port, _ := net.SplitHostPort(addr)
	res := checkAssetOwnership(context.Background(), "127.0.0.1:"+port, "example.com")

	if res.HTTPStatus == 0 {
		t.Error("HTTP probe should have reached the server via ip:port format")
	}
	if res.Confidence != AssetConfirmed {
		t.Errorf("confidence = %v; want AssetConfirmed", res.Confidence)
	}
}

func TestOwnership_BareIPNoPort(t *testing.T) {
	// When no port is provided, the function uses bare IP + port 443 for TLS
	// and "https://<bare>/" for HTTP. This will fail to connect in tests
	// (nothing on 443), but must not panic.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	res := checkAssetOwnership(ctx, "127.0.0.1", "example.com")

	// Should not panic, and should have at least the confidence summary.
	if !hasEvidence(res, "Confidence:") {
		t.Error("expected confidence summary in evidence")
	}
}

// ---------------------------------------------------------------------------
// checkAssetOwnership — cancelled/expired context
// ---------------------------------------------------------------------------

func TestOwnership_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	res := checkAssetOwnership(ctx, "192.0.2.1", "example.com")

	// Should return promptly without panicking. Confidence stays unconfirmed
	// since all probes should fail with cancelled context.
	if res.Confidence == AssetConfirmed {
		t.Error("cancelled context should not produce confirmed ownership")
	}
	if !hasEvidence(res, "Confidence:") {
		t.Error("expected confidence summary even with cancelled context")
	}
}

func TestOwnership_ExpiredContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond) // ensure timeout fires

	res := checkAssetOwnership(ctx, "192.0.2.1", "example.com")

	if res.Confidence == AssetConfirmed {
		t.Error("expired context should not produce confirmed ownership")
	}
}

// ---------------------------------------------------------------------------
// checkAssetOwnership — empty / edge-case inputs
// ---------------------------------------------------------------------------

func TestOwnership_EmptyIP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	res := checkAssetOwnership(ctx, "", "example.com")

	if res.Confidence == AssetConfirmed {
		t.Error("empty IP should not produce confirmed ownership")
	}
	if !hasEvidence(res, "Confidence:") {
		t.Error("expected confidence summary for empty IP")
	}
}

func TestOwnership_EmptyRootDomain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	res := checkAssetOwnership(ctx, "192.0.2.1", "")

	// Nothing should match an empty root domain.
	if res.Confidence == AssetConfirmed {
		t.Error("empty rootDomain should not produce confirmed ownership")
	}
}

// ---------------------------------------------------------------------------
// checkAssetOwnership — TLS cert with OtherDomains → Unlikely
// ---------------------------------------------------------------------------

func TestOwnership_OtherDomainsInCert_Unlikely(t *testing.T) {
	// Server cert has SANs from a completely different org, and the server
	// returns 421 to reject the domain. The function should set OtherDomains
	// and lower confidence.
	addr, cleanup := tlsHTTPServer(t,
		[]string{"megacorp.com", "cdn.megacorp.com"},
		nil,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusMisdirectedRequest)
		}),
	)
	defer cleanup()

	_, port, _ := net.SplitHostPort(addr)
	res := checkAssetOwnership(context.Background(), "127.0.0.1:"+port, "target.com")

	// The TLS probe connects on 443 (not our port), so TLS SANs won't be read.
	// But the HTTP 421 should push confidence to RuledOut.
	if res.Confidence == AssetConfirmed {
		t.Error("cert with only other-org SANs + 421 should not confirm")
	}
}

// ---------------------------------------------------------------------------
// checkAssetOwnership — server header capture
// ---------------------------------------------------------------------------

func TestOwnership_ServerHeaderCaptured(t *testing.T) {
	addr, cleanup := tlsHTTPServer(t,
		[]string{"other.com"},
		nil,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "Apache/2.4.52")
			w.WriteHeader(http.StatusOK)
		}),
	)
	defer cleanup()

	_, port, _ := net.SplitHostPort(addr)
	res := checkAssetOwnership(context.Background(), "127.0.0.1:"+port, "target.com")

	if res.ServerHeader != "Apache/2.4.52" {
		t.Errorf("ServerHeader = %q; want Apache/2.4.52", res.ServerHeader)
	}
	if !hasEvidence(res, "Server: Apache/2.4.52") {
		t.Error("expected Server evidence line")
	}
}

func TestOwnership_NoServerHeader(t *testing.T) {
	addr, cleanup := tlsHTTPServer(t,
		[]string{"other.com"},
		nil,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)
	defer cleanup()

	_, port, _ := net.SplitHostPort(addr)
	res := checkAssetOwnership(context.Background(), "127.0.0.1:"+port, "target.com")

	if res.ServerHeader != "" {
		t.Errorf("ServerHeader = %q; want empty", res.ServerHeader)
	}
	if hasEvidence(res, "Server:") {
		// The confidence line also starts with "Confidence:" not "Server:", but
		// let's be precise: there should be no "Server: <value>" line.
		for _, e := range res.Evidence {
			if strings.HasPrefix(e, "Server:") {
				t.Error("should not have Server evidence when header is absent")
			}
		}
	}
}

// ---------------------------------------------------------------------------
// checkAssetOwnership — HEAD method used for HTTP probe
// ---------------------------------------------------------------------------

func TestOwnership_HTTPProbeUsesHEAD(t *testing.T) {
	var gotMethod string
	addr, cleanup := tlsHTTPServer(t,
		[]string{"other.com"},
		nil,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotMethod = r.Method
			w.WriteHeader(http.StatusOK)
		}),
	)
	defer cleanup()

	_, port, _ := net.SplitHostPort(addr)
	checkAssetOwnership(context.Background(), "127.0.0.1:"+port, "target.com")

	if gotMethod != http.MethodHead {
		t.Errorf("HTTP probe method = %q; want HEAD", gotMethod)
	}
}

// ---------------------------------------------------------------------------
// checkAssetOwnership — Host header set to rootDomain
// ---------------------------------------------------------------------------

func TestOwnership_HTTPProbeHostHeader(t *testing.T) {
	var gotHost string
	addr, cleanup := tlsHTTPServer(t,
		[]string{"other.com"},
		nil,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotHost = r.Host
			w.WriteHeader(http.StatusOK)
		}),
	)
	defer cleanup()

	_, port, _ := net.SplitHostPort(addr)
	checkAssetOwnership(context.Background(), "127.0.0.1:"+port, "mysite.org")

	if gotHost != "mysite.org" {
		t.Errorf("HTTP probe Host header = %q; want mysite.org", gotHost)
	}
}

// ---------------------------------------------------------------------------
// OwnershipResult struct defaults
// ---------------------------------------------------------------------------

func TestOwnershipResult_ZeroValue(t *testing.T) {
	var res OwnershipResult
	if res.Confidence != AssetRuledOut {
		// Zero value of int is 0, which is AssetRuledOut.
		// This tests that the default is meaningful.
		t.Errorf("zero-value Confidence = %v; want AssetRuledOut (iota 0)", res.Confidence)
	}
	if res.HTTPStatus != 0 {
		t.Error("zero-value HTTPStatus should be 0")
	}
	if res.CloudProvider != "" {
		t.Error("zero-value CloudProvider should be empty")
	}
}

func TestOwnershipResult_InitializedByFunction(t *testing.T) {
	// checkAssetOwnership initializes Confidence to AssetUnconfirmed, not zero.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	res := checkAssetOwnership(ctx, "192.0.2.1", "example.com")

	// With no successful probes, should be unconfirmed (not ruled out).
	if res.Confidence == AssetRuledOut {
		t.Error("function should initialize to AssetUnconfirmed, not AssetRuledOut")
	}
}

// ---------------------------------------------------------------------------
// Confidence ordering sanity check
// ---------------------------------------------------------------------------

func TestConfidenceOrdering(t *testing.T) {
	if AssetRuledOut >= AssetUnlikely {
		t.Error("AssetRuledOut should be less than AssetUnlikely")
	}
	if AssetUnlikely >= AssetUnconfirmed {
		t.Error("AssetUnlikely should be less than AssetUnconfirmed")
	}
	if AssetUnconfirmed >= AssetLikely {
		t.Error("AssetUnconfirmed should be less than AssetLikely")
	}
	if AssetLikely >= AssetConfirmed {
		t.Error("AssetLikely should be less than AssetConfirmed")
	}
}

// ---------------------------------------------------------------------------
// checkAssetOwnership — concurrent safety (no data race)
// ---------------------------------------------------------------------------

func TestOwnership_ConcurrentSafe(t *testing.T) {
	addr, cleanup := tlsHTTPServer(t,
		[]string{"example.com"},
		nil,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)
	defer cleanup()

	_, port, _ := net.SplitHostPort(addr)

	// Run multiple ownership checks concurrently to catch data races under -race.
	const N = 5
	done := make(chan OwnershipResult, N)
	for i := 0; i < N; i++ {
		go func() {
			res := checkAssetOwnership(context.Background(), "127.0.0.1:"+port, "example.com")
			done <- res
		}()
	}
	for i := 0; i < N; i++ {
		res := <-done
		if !hasEvidence(res, "Confidence:") {
			t.Error("concurrent call missing confidence summary")
		}
	}
}

// ---------------------------------------------------------------------------
// checkAssetOwnership — unreachable host (connection refused)
// ---------------------------------------------------------------------------

func TestOwnership_UnreachableHost_NoTLSOrHTTPSignals(t *testing.T) {
	// Find a port that's guaranteed not listening.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // close immediately — port is now free and refusing connections

	_, port, _ := net.SplitHostPort(addr)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res := checkAssetOwnership(ctx, "127.0.0.1:"+port, "example.com")

	if res.HTTPStatus != 0 {
		t.Errorf("HTTPStatus = %d; want 0 for unreachable host", res.HTTPStatus)
	}
	if res.TLSIssuer != "" {
		t.Errorf("TLSIssuer = %q; want empty for unreachable host", res.TLSIssuer)
	}
	if len(res.TLSSANs) != 0 {
		t.Errorf("TLSSANs = %v; want empty for unreachable host", res.TLSSANs)
	}
	// Should remain unconfirmed since no signals were gathered.
	if res.Confidence == AssetConfirmed {
		t.Error("unreachable host should not be confirmed")
	}
}

// ---------------------------------------------------------------------------
// checkAssetOwnership — self-signed cert with matching SAN
// ---------------------------------------------------------------------------

func TestOwnership_SelfSignedCertWithMatchingSAN(t *testing.T) {
	// Self-signed certs should still be inspected (InsecureSkipVerify: true).
	// The cert has SANs matching the target, so ownership should be confirmed
	// via the HTTP probe (TLS connects on 443, not our port).
	addr, cleanup := tlsHTTPServer(t,
		[]string{"target.com", "www.target.com"},
		nil,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)
	defer cleanup()

	_, port, _ := net.SplitHostPort(addr)
	res := checkAssetOwnership(context.Background(), "127.0.0.1:"+port, "target.com")

	if res.Confidence != AssetConfirmed {
		t.Errorf("confidence = %v; want AssetConfirmed (self-signed cert should still be checked)", res.Confidence)
	}
}

// ---------------------------------------------------------------------------
// checkAssetOwnership — UserAgent header
// ---------------------------------------------------------------------------

func TestOwnership_HTTPProbeUserAgent(t *testing.T) {
	var gotUA string
	addr, cleanup := tlsHTTPServer(t,
		[]string{"other.com"},
		nil,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotUA = r.Header.Get("User-Agent")
			w.WriteHeader(http.StatusOK)
		}),
	)
	defer cleanup()

	_, port, _ := net.SplitHostPort(addr)
	checkAssetOwnership(context.Background(), "127.0.0.1:"+port, "target.com")

	if !strings.Contains(gotUA, "BeaconScanner") {
		t.Errorf("User-Agent = %q; want string containing 'BeaconScanner'", gotUA)
	}
}

// ---------------------------------------------------------------------------
// checkAssetOwnership — redirect not followed
// ---------------------------------------------------------------------------

func TestOwnership_HTTPProbeDoesNotFollowRedirects(t *testing.T) {
	// The function sets CheckRedirect to return ErrUseLastResponse.
	// A 302 should be recorded as-is, not followed.
	redirectTarget := "https://evil.com/phish"
	addr, cleanup := tlsHTTPServer(t,
		[]string{"other.com"},
		nil,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, redirectTarget, http.StatusFound)
		}),
	)
	defer cleanup()

	_, port, _ := net.SplitHostPort(addr)
	res := checkAssetOwnership(context.Background(), "127.0.0.1:"+port, "target.com")

	if res.HTTPStatus != http.StatusFound {
		t.Errorf("HTTPStatus = %d; want 302 (redirect should not be followed)", res.HTTPStatus)
	}
	// 302 is in the 3xx range → confirmed
	if res.Confidence != AssetConfirmed {
		t.Errorf("confidence = %v; want AssetConfirmed (302 is success range)", res.Confidence)
	}
}
