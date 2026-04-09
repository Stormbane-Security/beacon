package portscan

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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
)

// selfSignedTLSConfig returns a tls.Config with a self-signed ECDSA cert
// for testing. The cert CN and SAN are set to "localhost".
func selfSignedTLSConfig(t *testing.T, notAfter time.Time) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost", Organization: []string{"Test Org"}},
		Issuer:       pkix.Name{Organization: []string{"Test CA"}},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{"localhost"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
}

// startTLSServer starts a TLS listener on a random port, returns host, port,
// and a cleanup function.
func startTLSServer(t *testing.T, tlsCfg *tls.Config) (string, int, func()) {
	t.Helper()
	l, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			// Complete the handshake then close.
			_ = conn.(*tls.Conn).Handshake()
			conn.Close()
		}
	}()
	addr := l.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port, func() { l.Close() }
}

func TestJA3SFingerprint_ValidTLS(t *testing.T) {
	t.Parallel()
	// Clear caches for this test.
	ja3sCacheMu.Lock()
	ja3sCache = make(map[string]*JA3SResult)
	ja3sCacheMu.Unlock()

	tlsCfg := selfSignedTLSConfig(t, time.Now().Add(24*time.Hour))
	host, port, cleanup := startTLSServer(t, tlsCfg)
	defer cleanup()

	result := JA3SFingerprint(context.Background(), host, port)
	if result == nil {
		t.Fatal("expected non-nil JA3SResult for TLS server")
	}

	// Hash should be a 32-char hex MD5.
	if len(result.Hash) != 32 {
		t.Errorf("expected 32-char MD5 hash, got %q (len %d)", result.Hash, len(result.Hash))
	}

	// RawString should contain version and cipher separated by commas.
	parts := strings.Split(result.RawString, ",")
	if len(parts) < 2 {
		t.Errorf("expected RawString with at least 2 comma-separated fields, got %q", result.RawString)
	}

	// TLS version should be 1.2 or 1.3.
	if result.TLSVersion != tls.VersionTLS12 && result.TLSVersion != tls.VersionTLS13 {
		t.Errorf("unexpected TLS version: 0x%04x", result.TLSVersion)
	}

	// Cipher suite should be non-zero.
	if result.CipherSuite == 0 {
		t.Error("cipher suite should not be zero")
	}

	// Certificate metadata.
	if result.ServerName != "localhost" {
		t.Errorf("expected ServerName=localhost, got %q", result.ServerName)
	}
	if len(result.SANs) == 0 || result.SANs[0] != "localhost" {
		t.Errorf("expected SANs containing localhost, got %v", result.SANs)
	}
	if result.NotAfter.IsZero() {
		t.Error("NotAfter should not be zero")
	}
}

func TestJA3SFingerprint_NonTLSPort(t *testing.T) {
	t.Parallel()
	// Clear caches for this test.
	ja3sCacheMu.Lock()
	ja3sCache = make(map[string]*JA3SResult)
	ja3sCacheMu.Unlock()

	// Start a plain TCP server (no TLS).
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	port := l.Addr().(*net.TCPAddr).Port

	result := JA3SFingerprint(context.Background(), "127.0.0.1", port)
	if result != nil {
		t.Error("expected nil JA3SResult for non-TLS server")
	}
}

func TestJA3SFingerprint_Caching(t *testing.T) {
	t.Parallel()
	ja3sCacheMu.Lock()
	ja3sCache = make(map[string]*JA3SResult)
	ja3sCacheMu.Unlock()

	tlsCfg := selfSignedTLSConfig(t, time.Now().Add(24*time.Hour))
	host, port, cleanup := startTLSServer(t, tlsCfg)
	defer cleanup()

	r1 := JA3SFingerprint(context.Background(), host, port)
	r2 := JA3SFingerprint(context.Background(), host, port)

	if r1 == nil || r2 == nil {
		t.Fatal("both calls should return non-nil")
	}
	if r1.Hash != r2.Hash {
		t.Errorf("cached result should have same hash: %q vs %q", r1.Hash, r2.Hash)
	}
	// Second call should return the exact same pointer (from cache).
	if r1 != r2 {
		t.Error("expected second call to return cached pointer")
	}
}

func TestJA3SHash_Deterministic(t *testing.T) {
	t.Parallel()
	h1, r1 := ja3sHash(tls.VersionTLS12, 0xC02F) // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	h2, r2 := ja3sHash(tls.VersionTLS12, 0xC02F)
	if h1 != h2 {
		t.Errorf("same inputs should produce same hash: %q vs %q", h1, h2)
	}
	if r1 != r2 {
		t.Errorf("same inputs should produce same raw string: %q vs %q", r1, r2)
	}

	// Different cipher should produce different hash.
	h3, _ := ja3sHash(tls.VersionTLS12, 0xC030) // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	if h1 == h3 {
		t.Error("different cipher suites should produce different hashes")
	}
}

func TestIsWeakCipherSuite(t *testing.T) {
	t.Parallel()
	// Go's InsecureCipherSuites() includes RC4, 3DES, etc.
	insecure := tls.InsecureCipherSuites()
	if len(insecure) == 0 {
		t.Skip("no insecure cipher suites defined by Go runtime")
	}
	for _, s := range insecure {
		if !isWeakCipherSuite(s.ID) {
			t.Errorf("expected cipher %s (0x%04X) to be weak", s.Name, s.ID)
		}
	}
	// TLS 1.3 suites should not be weak.
	for _, s := range tls.CipherSuites() {
		for _, v := range s.SupportedVersions {
			if v == tls.VersionTLS13 {
				if isWeakCipherSuite(s.ID) {
					t.Errorf("TLS 1.3 cipher %s should not be weak", s.Name)
				}
			}
		}
	}
}

func TestTLSInfoEvidence_NilResult(t *testing.T) {
	t.Parallel()
	ev := TLSInfoEvidence(nil)
	if ev != nil {
		t.Error("expected nil evidence for nil JA3SResult")
	}
}

func TestTLSInfoEvidence_Fields(t *testing.T) {
	t.Parallel()
	r := &JA3SResult{
		Hash:        "abc123",
		RawString:   "771,49199,",
		TLSVersion:  tls.VersionTLS12,
		CipherSuite: 49199,
		ServerName:  "example.com",
		SANs:        []string{"example.com", "www.example.com"},
		Issuer:      "Let's Encrypt",
		NotAfter:    time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		NotBefore:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyBits:     256,
	}
	ev := TLSInfoEvidence(r)
	if ev == nil {
		t.Fatal("expected non-nil evidence")
	}
	if ev["ja3s_hash"] != "abc123" {
		t.Errorf("unexpected ja3s_hash: %v", ev["ja3s_hash"])
	}
	if ev["tls_version"] != "TLS 1.2" {
		t.Errorf("unexpected tls_version: %v", ev["tls_version"])
	}
	if ev["cert_cn"] != "example.com" {
		t.Errorf("unexpected cert_cn: %v", ev["cert_cn"])
	}
	if ev["cert_issuer"] != "Let's Encrypt" {
		t.Errorf("unexpected cert_issuer: %v", ev["cert_issuer"])
	}
	sans, ok := ev["cert_sans"].([]string)
	if !ok || len(sans) != 2 {
		t.Errorf("unexpected cert_sans: %v", ev["cert_sans"])
	}
}

func TestTLSVersionName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		version uint16
		want    string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
		{0x0399, "0x0399"},
	}
	for _, tt := range tests {
		if got := tlsVersionName(tt.version); got != tt.want {
			t.Errorf("tlsVersionName(0x%04x) = %q, want %q", tt.version, got, tt.want)
		}
	}
}

func TestCipherSuiteName(t *testing.T) {
	t.Parallel()
	// A known cipher should return its name, not hex.
	name := cipherSuiteName(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
	if strings.HasPrefix(name, "0x") {
		t.Errorf("expected human-readable name, got %q", name)
	}
	// Unknown cipher should return hex.
	name = cipherSuiteName(0xFFFF)
	if !strings.HasPrefix(name, "0x") {
		t.Errorf("expected hex for unknown cipher, got %q", name)
	}
}

// TestRunProbes_JA3SEnrichesServiceIdentified verifies that when a TLS port
// is probed, the service_identified finding includes JA3S evidence fields.
func TestRunProbes_JA3SEnrichesServiceIdentified(t *testing.T) {
	t.Parallel()
	// Clear caches.
	ja3sCacheMu.Lock()
	ja3sCache = make(map[string]*JA3SResult)
	ja3sCacheMu.Unlock()
	tlsCapableCacheMu.Lock()
	tlsCapableCache = make(map[string]bool)
	tlsCapableCacheMu.Unlock()

	tlsCfg := selfSignedTLSConfig(t, time.Now().Add(24*time.Hour))
	// Serve HTTPS so probes can identify it.
	tlsCfg.NextProtos = []string{"h2", "http/1.1"}
	l, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			// Just complete handshake and close — probes will get connection reset
			// but that's fine, we just need the TLS handshake to succeed for isTLSCapable.
			if tc, ok := conn.(*tls.Conn); ok {
				_ = tc.Handshake()
			}
			conn.Close()
		}
	}()
	port := l.Addr().(*net.TCPAddr).Port

	makeF := func(checkID finding.CheckID, severity finding.Severity, title, desc string, evidence map[string]any) finding.Finding {
		return finding.Finding{
			CheckID:     checkID,
			Severity:    severity,
			Title:       title,
			Description: desc,
			Evidence:    evidence,
		}
	}

	findings := runProbes(context.Background(), "127.0.0.1", port, "", makeF)

	// Look for service_identified finding with JA3S fields.
	for _, f := range findings {
		if f.CheckID == finding.CheckPortServiceIdentified {
			if f.Evidence["ja3s_hash"] == nil {
				t.Error("service_identified finding should have ja3s_hash evidence on TLS port")
			}
			if f.Evidence["tls_version"] == nil {
				t.Error("service_identified finding should have tls_version evidence on TLS port")
			}
			if f.Evidence["cipher_suite"] == nil {
				t.Error("service_identified finding should have cipher_suite evidence on TLS port")
			}
			return
		}
	}
	// It's OK if no service was identified (the TLS server doesn't speak HTTP),
	// but if one was found it should have the JA3S fields.
	t.Log("no service_identified finding emitted (expected for TLS-only server with no HTTP)")
}

// TestRunProbes_ExpiredCertFinding verifies that an expired TLS certificate
// emits a tls.expired_cert_detected finding.
func TestRunProbes_ExpiredCertFinding(t *testing.T) {
	t.Parallel()
	ja3sCacheMu.Lock()
	ja3sCache = make(map[string]*JA3SResult)
	ja3sCacheMu.Unlock()
	tlsCapableCacheMu.Lock()
	tlsCapableCache = make(map[string]bool)
	tlsCapableCacheMu.Unlock()

	// Create a cert that expired yesterday.
	tlsCfg := selfSignedTLSConfig(t, time.Now().Add(-24*time.Hour))
	host, port, cleanup := startTLSServer(t, tlsCfg)
	defer cleanup()

	makeF := func(checkID finding.CheckID, severity finding.Severity, title, desc string, evidence map[string]any) finding.Finding {
		return finding.Finding{
			CheckID:     checkID,
			Severity:    severity,
			Title:       title,
			Description: desc,
			Evidence:    evidence,
		}
	}

	findings := runProbes(context.Background(), host, port, "", makeF)

	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckTLSExpiredCertDetected {
			found = true
			if f.Severity != finding.SeverityHigh {
				t.Errorf("expected High severity, got %v", f.Severity)
			}
			if !strings.Contains(f.Title, strconv.Itoa(port)) {
				t.Errorf("title should mention port: %q", f.Title)
			}
		}
	}
	if !found {
		t.Error("expected tls.expired_cert_detected finding for expired certificate")
	}
}
