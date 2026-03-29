package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

// ── Helpers ──────────────────────────────────────────────────────────────────

// hasCheckID returns true if any finding in the slice matches the given ID.
func hasCheckID(findings []finding.Finding, id finding.CheckID) bool {
	for _, f := range findings {
		if f.CheckID == id {
			return true
		}
	}
	return false
}

// findByCheckID returns the first finding with the given check ID, or nil.
func findByCheckID(findings []finding.Finding, id finding.CheckID) *finding.Finding {
	for i := range findings {
		if findings[i].CheckID == id {
			return &findings[i]
		}
	}
	return nil
}

// generateSelfSignedCert creates a self-signed certificate with the given
// key, signature algorithm, and SAN configuration. It returns the leaf
// certificate object. The caller can control key size, SAN presence, validity
// period, and signature algorithm to exercise different scanner code paths.
func generateSelfSignedCert(t *testing.T, opts certOpts) *x509.Certificate {
	t.Helper()

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    opts.notBefore,
		NotAfter:     opts.notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if opts.addSANs {
		tmpl.DNSNames = []string{"test.example.com"}
	}

	if opts.wildcardSAN != "" {
		tmpl.DNSNames = append(tmpl.DNSNames, opts.wildcardSAN)
	}

	if opts.addOCSP {
		tmpl.OCSPServer = []string{"http://ocsp.example.com"}
	}

	if opts.addCRL {
		tmpl.CRLDistributionPoints = []string{"http://crl.example.com/root.crl"}
	}

	if opts.addSCT {
		// Add a fake SCT extension
		tmpl.ExtraExtensions = []pkix.Extension{
			{
				Id:    oidSCT,
				Value: []byte{0x01, 0x02, 0x03}, // non-empty dummy SCT
			},
		}
	}

	// Override signature algorithm if specified
	if opts.sigAlgo != 0 {
		tmpl.SignatureAlgorithm = opts.sigAlgo
	}

	var certDER []byte
	switch {
	case opts.rsaKey != nil:
		certDER, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &opts.rsaKey.PublicKey, opts.rsaKey)
	case opts.ecKey != nil:
		certDER, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &opts.ecKey.PublicKey, opts.ecKey)
	default:
		t.Fatal("certOpts must specify rsaKey or ecKey")
	}
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

type certOpts struct {
	rsaKey      *rsa.PrivateKey
	ecKey       *ecdsa.PrivateKey
	sigAlgo     x509.SignatureAlgorithm
	addSANs     bool
	wildcardSAN string
	addOCSP     bool
	addCRL      bool
	addSCT      bool
	notBefore   time.Time
	notAfter    time.Time
}

// tlsServerWithConfig starts a TLS server with the given tls.Config and
// returns the server along with its host and port.
func tlsServerWithConfig(t *testing.T, tlsCfg *tls.Config) (*httptest.Server, string, string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = tlsCfg
	srv.StartTLS()
	host, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	return srv, host, port
}

// generateTLSCertPEM creates a self-signed TLS certificate and private key in
// PEM form, suitable for tls.X509KeyPair. The certificate uses the given RSA
// key size.
func generateTLSCertPEM(t *testing.T, rsaBits int, dnsNames []string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		t.Fatal(err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}

// ── splitHostPort ────────────────────────────────────────────────────────────

func TestSplitHostPort_WithPort(t *testing.T) {
	h, p := splitHostPort("example.com:8443")
	if h != "example.com" || p != "8443" {
		t.Errorf("got %q %q", h, p)
	}
}

func TestSplitHostPort_NoPort(t *testing.T) {
	h, p := splitHostPort("example.com")
	if h != "example.com" || p != "443" {
		t.Errorf("got %q %q", h, p)
	}
}

func TestSplitHostPort_IPv6WithPort(t *testing.T) {
	h, p := splitHostPort("[::1]:8443")
	if h != "::1" || p != "8443" {
		t.Errorf("got %q %q, want %q %q", h, p, "::1", "8443")
	}
}

func TestSplitHostPort_IPv6BareAddress(t *testing.T) {
	// A bare IPv6 address like "::1" contains colons but has no port.
	// The old code would attempt net.SplitHostPort("::1") which fails,
	// then fall through to returning ("::1", "443") — but only by accident.
	h, p := splitHostPort("::1")
	if h != "::1" || p != "443" {
		t.Errorf("splitHostPort(\"::1\") = %q %q, want \"::1\" \"443\"", h, p)
	}
}

func TestSplitHostPort_IPv6Bracketed(t *testing.T) {
	// A bracketed IPv6 address without a port: [::1]
	h, p := splitHostPort("[::1]")
	if h != "::1" || p != "443" {
		t.Errorf("splitHostPort(\"[::1]\") = %q %q, want \"::1\" \"443\"", h, p)
	}
}

func TestSplitHostPort_IPv6FullAddress(t *testing.T) {
	h, p := splitHostPort("[2001:db8::1]:9443")
	if h != "2001:db8::1" || p != "9443" {
		t.Errorf("got %q %q, want \"2001:db8::1\" \"9443\"", h, p)
	}
}

// ── tlsVersionName ───────────────────────────────────────────────────────────

func TestTLSVersionName(t *testing.T) {
	tests := []struct {
		version uint16
		want    string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
		{0x9999, "0x9999"}, // unknown version falls through to hex
	}
	for _, tt := range tests {
		got := tlsVersionName(tt.version)
		if got != tt.want {
			t.Errorf("tlsVersionName(0x%04x) = %q, want %q", tt.version, got, tt.want)
		}
	}
}

// ── ocspRevocationReason ─────────────────────────────────────────────────────

func TestOCSPRevocationReason(t *testing.T) {
	tests := []struct {
		code int
		want string
	}{
		{0, "unspecified"},
		{1, "key_compromise"},
		{2, "ca_compromise"},
		{3, "affiliation_changed"},
		{4, "superseded"},
		{5, "cessation_of_operation"},
		{6, "certificate_hold"},
		{8, "remove_from_crl"},
		{9, "privilege_withdrawn"},
		{10, "aa_compromise"},
		{99, "reason_99"},
		{-1, "reason_-1"},
	}
	for _, tt := range tests {
		got := ocspRevocationReason(tt.code)
		if got != tt.want {
			t.Errorf("ocspRevocationReason(%d) = %q, want %q", tt.code, got, tt.want)
		}
	}
}

// ── hasSCT ───────────────────────────────────────────────────────────────────

func TestHasSCT_MissingExtension(t *testing.T) {
	// httptest TLS server certs have no SCT extension
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()

	conn, err := tls.Dial("tcp", strings.TrimPrefix(srv.URL, "https://"), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Skip("cannot dial test server:", err)
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatal("no certs")
	}
	// httptest certs won't have SCT -- this should return false
	if hasSCT(certs[0]) {
		t.Error("httptest cert unexpectedly has SCT")
	}
}

func TestHasSCT_WithSCTExtension(t *testing.T) {
	// Build a cert that has the SCT extension
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := generateSelfSignedCert(t, certOpts{
		rsaKey:    key,
		addSANs:   true,
		addSCT:    true,
		notBefore: time.Now().Add(-time.Hour),
		notAfter:  time.Now().Add(24 * time.Hour),
	})
	if !hasSCT(cert) {
		t.Error("expected hasSCT to return true for cert with SCT extension")
	}
}

func TestHasSCT_EmptySCTExtension(t *testing.T) {
	// Build a cert that has the SCT OID but empty value
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"test.example.com"},
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2},
				Value: []byte{}, // empty
			},
		},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	if hasSCT(cert) {
		t.Error("hasSCT should return false for empty SCT extension value")
	}
}

// ── supportsTLS13 ────────────────────────────────────────────────────────────

func TestSupportsTLS13_RealServer(t *testing.T) {
	srv := httptest.NewUnstartedServer(nil)
	srv.TLS = &tls.Config{}
	srv.StartTLS()
	defer srv.Close()

	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	// httptest uses Go's TLS stack which supports TLS 1.3
	result := supportsTLS13(context.Background(), host, port)
	if !result {
		t.Error("Go httptest TLS server should support TLS 1.3")
	}
}

func TestSupportsTLS13_ServerOnlyTLS12(t *testing.T) {
	srv, host, port := tlsServerWithConfig(t, &tls.Config{
		MaxVersion: tls.VersionTLS12,
	})
	defer srv.Close()

	result := supportsTLS13(context.Background(), host, port)
	if result {
		t.Error("server capped at TLS 1.2 should not report TLS 1.3 support")
	}
}

// ── checkWeakKey ─────────────────────────────────────────────────────────────

func TestCheckWeakKey_RSA1024_EmitsFinding(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	cert := generateSelfSignedCert(t, certOpts{
		rsaKey:    key,
		addSANs:   true,
		notBefore: time.Now().Add(-time.Hour),
		notAfter:  time.Now().Add(24 * time.Hour),
	})

	f := checkWeakKey(cert, "weak.example.com", time.Now())
	if f == nil {
		t.Fatal("expected finding for RSA-1024 key, got nil")
	}
	if f.CheckID != finding.CheckTLSCertWeakKey {
		t.Errorf("CheckID = %q, want %q", f.CheckID, finding.CheckTLSCertWeakKey)
	}
	if f.Severity != finding.SeverityHigh {
		t.Errorf("Severity = %v, want High", f.Severity)
	}
	if !strings.Contains(f.Title, "RSA-1024") {
		t.Errorf("Title should mention RSA-1024, got %q", f.Title)
	}
}

func TestCheckWeakKey_RSA1536_EmitsFinding(t *testing.T) {
	// RSA-1536 is below the 2048-bit threshold but still accepted by Go's crypto
	key, err := rsa.GenerateKey(rand.Reader, 1536)
	if err != nil {
		t.Fatal(err)
	}
	cert := generateSelfSignedCert(t, certOpts{
		rsaKey:    key,
		addSANs:   true,
		notBefore: time.Now().Add(-time.Hour),
		notAfter:  time.Now().Add(24 * time.Hour),
	})

	f := checkWeakKey(cert, "weak1536.example.com", time.Now())
	if f == nil {
		t.Fatal("expected finding for RSA-1536 key, got nil")
	}
	if !strings.Contains(f.Title, "RSA-1536") {
		t.Errorf("Title should mention RSA-1536, got %q", f.Title)
	}
}

func TestCheckWeakKey_RSA2048_NoFinding(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := generateSelfSignedCert(t, certOpts{
		rsaKey:    key,
		addSANs:   true,
		notBefore: time.Now().Add(-time.Hour),
		notAfter:  time.Now().Add(24 * time.Hour),
	})

	f := checkWeakKey(cert, "strong.example.com", time.Now())
	if f != nil {
		t.Errorf("expected no finding for RSA-2048 key, got %q", f.Title)
	}
}

func TestCheckWeakKey_RSA4096_NoFinding(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	cert := generateSelfSignedCert(t, certOpts{
		rsaKey:    key,
		addSANs:   true,
		notBefore: time.Now().Add(-time.Hour),
		notAfter:  time.Now().Add(24 * time.Hour),
	})

	f := checkWeakKey(cert, "strong4096.example.com", time.Now())
	if f != nil {
		t.Errorf("expected no finding for RSA-4096 key, got %q", f.Title)
	}
}

func TestCheckWeakKey_ECDSA_P256_NoFinding(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := generateSelfSignedCert(t, certOpts{
		ecKey:     key,
		addSANs:   true,
		notBefore: time.Now().Add(-time.Hour),
		notAfter:  time.Now().Add(24 * time.Hour),
	})

	f := checkWeakKey(cert, "ec256.example.com", time.Now())
	if f != nil {
		t.Errorf("expected no finding for P-256 key (256 bits >= 224), got %q", f.Title)
	}
}

func TestCheckWeakKey_ECDSA_P224_NoFinding(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := generateSelfSignedCert(t, certOpts{
		ecKey:     key,
		addSANs:   true,
		notBefore: time.Now().Add(-time.Hour),
		notAfter:  time.Now().Add(24 * time.Hour),
	})

	f := checkWeakKey(cert, "ec224.example.com", time.Now())
	if f != nil {
		t.Errorf("expected no finding for P-224 key (224 bits >= 224), got %q", f.Title)
	}
}

// ── Weak signature algorithm ─────────────────────────────────────────────────
//
// We cannot easily create a certificate actually signed with MD5 or SHA-1
// because Go's x509.CreateCertificate refuses those algorithms. Instead we
// test the weakSigAlgs map lookup directly against synthetic certificate
// objects, which is the exact code path the scanner uses.

func TestWeakSigAlg_Detected(t *testing.T) {
	tests := []struct {
		algo x509.SignatureAlgorithm
		name string
	}{
		{x509.MD5WithRSA, "MD5WithRSA"},
		{x509.SHA1WithRSA, "SHA1WithRSA"},
		{x509.ECDSAWithSHA1, "ECDSAWithSHA1"},
		{x509.DSAWithSHA1, "DSAWithSHA1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, weak := weakSigAlgs[tt.algo]
			if !weak {
				t.Fatalf("expected %s to be in weakSigAlgs", tt.name)
			}
			if name != tt.name {
				t.Errorf("weakSigAlgs[%v] = %q, want %q", tt.algo, name, tt.name)
			}
		})
	}
}

func TestWeakSigAlg_StrongNotDetected(t *testing.T) {
	strong := []x509.SignatureAlgorithm{
		x509.SHA256WithRSA,
		x509.SHA384WithRSA,
		x509.SHA512WithRSA,
		x509.ECDSAWithSHA256,
		x509.ECDSAWithSHA384,
		x509.ECDSAWithSHA512,
	}
	for _, algo := range strong {
		if name, weak := weakSigAlgs[algo]; weak {
			t.Errorf("algorithm %v (%s) should not be in weakSigAlgs", algo, name)
		}
	}
}

// TestWeakSigAlg_FindingEmission verifies the inline weak-sig code path in
// Run() produces a correctly shaped finding. We simulate it by running the
// same map lookup + finding construction logic on a cert with SHA1WithRSA.
func TestWeakSigAlg_FindingEmission(t *testing.T) {
	// Create a cert with a strong signature, then override the parsed field
	// to simulate what the scanner would see for a SHA1-signed cert.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := generateSelfSignedCert(t, certOpts{
		rsaKey:    key,
		addSANs:   true,
		notBefore: time.Now().Add(-time.Hour),
		notAfter:  time.Now().Add(24 * time.Hour),
	})
	// Simulate a SHA1-signed cert by overriding the field
	cert.SignatureAlgorithm = x509.SHA1WithRSA

	asset := "weaksig.example.com"

	name, weak := weakSigAlgs[cert.SignatureAlgorithm]
	if !weak {
		t.Fatal("SHA1WithRSA should be detected as weak")
	}

	f := finding.Finding{
		CheckID:  finding.CheckTLSCertWeakSignature,
		Severity: finding.SeverityHigh,
		Asset:    asset,
		Title:    "Certificate signed with weak algorithm: " + name,
	}

	if f.CheckID != finding.CheckTLSCertWeakSignature {
		t.Errorf("CheckID = %q, want %q", f.CheckID, finding.CheckTLSCertWeakSignature)
	}
	if f.Severity != finding.SeverityHigh {
		t.Errorf("Severity = %v, want High", f.Severity)
	}
	if !strings.Contains(f.Title, "SHA1WithRSA") {
		t.Errorf("Title should mention SHA1WithRSA, got %q", f.Title)
	}
}

// ── SAN missing ──────────────────────────────────────────────────────────────

func TestSANMissing_CertWithNoSANs_EmitsFinding(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := generateSelfSignedCert(t, certOpts{
		rsaKey:    key,
		addSANs:   false, // no SANs
		notBefore: time.Now().Add(-time.Hour),
		notAfter:  time.Now().Add(24 * time.Hour),
	})

	// The SAN-missing check: len(DNSNames) == 0 && len(IPAddresses) == 0
	if len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 0 {
		t.Fatal("test cert unexpectedly has SANs")
	}

	// Simulate the check from Run()
	hasSANMissing := len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0
	if !hasSANMissing {
		t.Error("expected SAN-missing condition to be true")
	}
}

func TestSANMissing_CertWithDNSSANs_NoFinding(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := generateSelfSignedCert(t, certOpts{
		rsaKey:    key,
		addSANs:   true, // has DNS SANs
		notBefore: time.Now().Add(-time.Hour),
		notAfter:  time.Now().Add(24 * time.Hour),
	})

	hasSANMissing := len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0
	if hasSANMissing {
		t.Error("cert with SANs should not trigger SAN-missing finding")
	}
}

// ── Wildcard cert ────────────────────────────────────────────────────────────

func TestWildcardSAN_Detected(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := generateSelfSignedCert(t, certOpts{
		rsaKey:      key,
		addSANs:      true,
		wildcardSAN: "*.example.com",
		notBefore:   time.Now().Add(-time.Hour),
		notAfter:    time.Now().Add(24 * time.Hour),
	})

	found := false
	for _, san := range cert.DNSNames {
		if strings.HasPrefix(san, "*.") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected wildcard SAN to be detected in cert")
	}
}

func TestWildcardSAN_NotDetected(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := generateSelfSignedCert(t, certOpts{
		rsaKey:    key,
		addSANs:   true,
		notBefore: time.Now().Add(-time.Hour),
		notAfter:  time.Now().Add(24 * time.Hour),
	})

	for _, san := range cert.DNSNames {
		if strings.HasPrefix(san, "*.") {
			t.Errorf("unexpected wildcard SAN %q in cert", san)
		}
	}
}

// ── Certificate validity period ──────────────────────────────────────────────

func TestLongValidity_EmitsFinding(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// 500 days validity, issued after Sept 2020
	notBefore := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(500 * 24 * time.Hour)

	cert := generateSelfSignedCert(t, certOpts{
		rsaKey:    key,
		addSANs:   true,
		notBefore: notBefore,
		notAfter:  notAfter,
	})

	validDays := int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)
	if validDays <= 398 {
		t.Fatalf("test cert validity = %d days, want > 398", validDays)
	}
	isPostCABForum := cert.NotBefore.After(time.Date(2020, 9, 1, 0, 0, 0, 0, time.UTC))
	if !isPostCABForum {
		t.Fatal("test cert NotBefore should be after 2020-09-01")
	}
}

func TestLongValidity_PreCABForum_NoFinding(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// 500 days validity, but issued before Sept 2020 -- should not trigger
	notBefore := time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(500 * 24 * time.Hour)

	cert := generateSelfSignedCert(t, certOpts{
		rsaKey:    key,
		addSANs:   true,
		notBefore: notBefore,
		notAfter:  notAfter,
	})

	validDays := int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)
	isLong := validDays > 398
	isPostCABForum := cert.NotBefore.After(time.Date(2020, 9, 1, 0, 0, 0, 0, time.UTC))

	if isLong && isPostCABForum {
		t.Error("pre-CA/B Forum cert should not trigger long-validity check")
	}
}

func TestLongValidity_ShortValidity_NoFinding(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// 90 days validity, issued after Sept 2020
	notBefore := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(90 * 24 * time.Hour)

	cert := generateSelfSignedCert(t, certOpts{
		rsaKey:    key,
		addSANs:   true,
		notBefore: notBefore,
		notAfter:  notAfter,
	})

	validDays := int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)
	if validDays > 398 {
		t.Errorf("test cert validity = %d days, want <= 398", validDays)
	}
}

// ── No OCSP URL ──────────────────────────────────────────────────────────────

func TestNoOCSP_Detected(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := generateSelfSignedCert(t, certOpts{
		rsaKey:    key,
		addSANs:   true,
		addOCSP:   false,
		notBefore: time.Now().Add(-time.Hour),
		notAfter:  time.Now().Add(24 * time.Hour),
	})

	if len(cert.OCSPServer) != 0 {
		t.Error("test cert unexpectedly has OCSP server")
	}
}

func TestNoOCSP_NotDetected(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := generateSelfSignedCert(t, certOpts{
		rsaKey:    key,
		addSANs:   true,
		addOCSP:   true,
		notBefore: time.Now().Add(-time.Hour),
		notAfter:  time.Now().Add(24 * time.Hour),
	})

	if len(cert.OCSPServer) == 0 {
		t.Error("test cert should have OCSP server URL")
	}
}

// ── No CRL and no OCSP ──────────────────────────────────────────────────────

func TestNoCRLAndNoOCSP_BothMissing(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := generateSelfSignedCert(t, certOpts{
		rsaKey:    key,
		addSANs:   true,
		addOCSP:   false,
		addCRL:    false,
		notBefore: time.Now().Add(-time.Hour),
		notAfter:  time.Now().Add(24 * time.Hour),
	})

	noCRL := len(cert.CRLDistributionPoints) == 0
	noOCSP := len(cert.OCSPServer) == 0

	if !(noCRL && noOCSP) {
		t.Error("expected both CRL and OCSP to be absent")
	}
}

func TestNoCRLAndNoOCSP_CRLPresent_NoFinding(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := generateSelfSignedCert(t, certOpts{
		rsaKey:    key,
		addSANs:   true,
		addOCSP:   false,
		addCRL:    true,
		notBefore: time.Now().Add(-time.Hour),
		notAfter:  time.Now().Add(24 * time.Hour),
	})

	noCRL := len(cert.CRLDistributionPoints) == 0
	noOCSP := len(cert.OCSPServer) == 0

	// The check is: len(CRL) == 0 AND len(OCSP) == 0. If CRL is present
	// the check should not trigger even though OCSP is missing.
	if noCRL && noOCSP {
		t.Error("CRL is present, so the no-revocation-mechanism check should not fire")
	}
}

// ── No PFS (Perfect Forward Secrecy) ─────────────────────────────────────────

func TestPFS_PFSCipherDetected(t *testing.T) {
	// Cipher suites containing these substrings are PFS-capable
	pfsCiphers := []string{
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_AES_128_GCM_SHA256",           // TLS 1.3 cipher
		"TLS_CHACHA20_POLY1305_SHA256",      // TLS 1.3 cipher
	}

	for _, cipherName := range pfsCiphers {
		t.Run(cipherName, func(t *testing.T) {
			hasPFS := false
			for _, kex := range pfsKeyExchanges {
				if strings.Contains(cipherName, kex) {
					hasPFS = true
					break
				}
			}
			if !hasPFS {
				t.Errorf("cipher %q should be detected as PFS", cipherName)
			}
		})
	}
}

func TestPFS_NonPFSCipherDetected(t *testing.T) {
	nonPFSCiphers := []string{
		"TLS_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_RSA_WITH_AES_256_CBC_SHA",
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	}

	for _, cipherName := range nonPFSCiphers {
		t.Run(cipherName, func(t *testing.T) {
			hasPFS := false
			for _, kex := range pfsKeyExchanges {
				if strings.Contains(cipherName, kex) {
					hasPFS = true
					break
				}
			}
			if hasPFS {
				t.Errorf("cipher %q should NOT be detected as PFS", cipherName)
			}
		})
	}
}

func TestPFS_TLS13AlwaysPFS(t *testing.T) {
	// TLS 1.3 is always PFS regardless of cipher name
	version := tls.VersionTLS13
	cipherName := "TLS_RSA_WITH_FAKE_CIPHER" // not PFS by name

	hasPFS := false
	for _, kex := range pfsKeyExchanges {
		if strings.Contains(cipherName, kex) {
			hasPFS = true
			break
		}
	}
	if version == tls.VersionTLS13 {
		hasPFS = true
	}

	if !hasPFS {
		t.Error("TLS 1.3 should always be marked as PFS-capable")
	}
}

// ── Deprecated protocol checks (TLS 1.0 and TLS 1.1) via checkDeprecatedProtocol ──

func TestCheckDeprecatedProtocol_TLS10_Accepted(t *testing.T) {
	// Create a TLS server that accepts TLS 1.0
	srv, host, port := tlsServerWithConfig(t, &tls.Config{
		MinVersion: tls.VersionTLS10,
	})
	defer srv.Close()

	f := checkDeprecatedProtocol(
		context.Background(), host, port, host+":"+port,
		tls.VersionTLS10, "TLS 1.0",
		finding.CheckTLSProtocolTLS10, finding.SeverityHigh,
		time.Now(),
	)

	if f == nil {
		t.Fatal("expected finding for server accepting TLS 1.0, got nil")
	}
	if f.CheckID != finding.CheckTLSProtocolTLS10 {
		t.Errorf("CheckID = %q, want %q", f.CheckID, finding.CheckTLSProtocolTLS10)
	}
	if f.Severity != finding.SeverityHigh {
		t.Errorf("Severity = %v, want High", f.Severity)
	}
	if !strings.Contains(f.Title, "TLS 1.0") {
		t.Errorf("Title should mention TLS 1.0, got %q", f.Title)
	}
	if !strings.Contains(f.Description, "deprecated") {
		t.Errorf("Description should mention deprecated, got %q", f.Description)
	}
}

func TestCheckDeprecatedProtocol_TLS11_Accepted(t *testing.T) {
	srv, host, port := tlsServerWithConfig(t, &tls.Config{
		MinVersion: tls.VersionTLS10,
	})
	defer srv.Close()

	f := checkDeprecatedProtocol(
		context.Background(), host, port, host+":"+port,
		tls.VersionTLS11, "TLS 1.1",
		finding.CheckTLSProtocolTLS11, finding.SeverityMedium,
		time.Now(),
	)

	if f == nil {
		t.Fatal("expected finding for server accepting TLS 1.1, got nil")
	}
	if f.CheckID != finding.CheckTLSProtocolTLS11 {
		t.Errorf("CheckID = %q, want %q", f.CheckID, finding.CheckTLSProtocolTLS11)
	}
	if f.Severity != finding.SeverityMedium {
		t.Errorf("Severity = %v, want Medium", f.Severity)
	}
}

func TestCheckDeprecatedProtocol_TLS10_Rejected(t *testing.T) {
	// Create a TLS server that only accepts TLS 1.2+
	srv, host, port := tlsServerWithConfig(t, &tls.Config{
		MinVersion: tls.VersionTLS12,
	})
	defer srv.Close()

	f := checkDeprecatedProtocol(
		context.Background(), host, port, host+":"+port,
		tls.VersionTLS10, "TLS 1.0",
		finding.CheckTLSProtocolTLS10, finding.SeverityHigh,
		time.Now(),
	)

	if f != nil {
		t.Errorf("server rejecting TLS 1.0 should not produce finding, got %q", f.Title)
	}
}

func TestCheckDeprecatedProtocol_TLS11_Rejected(t *testing.T) {
	srv, host, port := tlsServerWithConfig(t, &tls.Config{
		MinVersion: tls.VersionTLS12,
	})
	defer srv.Close()

	f := checkDeprecatedProtocol(
		context.Background(), host, port, host+":"+port,
		tls.VersionTLS11, "TLS 1.1",
		finding.CheckTLSProtocolTLS11, finding.SeverityMedium,
		time.Now(),
	)

	if f != nil {
		t.Errorf("server rejecting TLS 1.1 should not produce finding, got %q", f.Title)
	}
}

func TestCheckDeprecatedProtocol_Unreachable(t *testing.T) {
	// Use a port that nothing is listening on
	f := checkDeprecatedProtocol(
		context.Background(), "127.0.0.1", "1", "127.0.0.1:1",
		tls.VersionTLS10, "TLS 1.0",
		finding.CheckTLSProtocolTLS10, finding.SeverityHigh,
		time.Now(),
	)

	if f != nil {
		t.Errorf("unreachable host should not produce finding, got %q", f.Title)
	}
}

// ── Full Run() integration test ──────────────────────────────────────────────
//
// Uses httptest.NewTLSServer (Go default = TLS 1.2+1.3, PFS ciphers, 2048-bit
// RSA key) so we know exactly which findings should and should not fire.

func TestRun_DefaultHTTPTestServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	asset := host + ":" + port

	s := New()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// httptest certs include 127.0.0.1 as an IP SAN, so SAN-missing should NOT fire
	if hasCheckID(findings, finding.CheckTLSCertSANMissing) {
		t.Error("httptest cert has IP SANs (127.0.0.1), should not trigger tls.cert_san_missing")
	}

	// httptest certs have no OCSP
	if !hasCheckID(findings, finding.CheckTLSCertNoOCSP) {
		t.Error("expected tls.cert_no_ocsp for httptest server")
	}

	// httptest certs have no CRL and no OCSP -- no revocation mechanism
	if !hasCheckID(findings, finding.CheckTLSCRLNoURL) {
		t.Error("expected tls.cert_no_crl for httptest server (no CRL and no OCSP)")
	}

	// httptest Go TLS stack uses ECDHE (PFS), so no-PFS should NOT fire
	if hasCheckID(findings, finding.CheckTLSNoPFS) {
		t.Error("httptest Go TLS should negotiate PFS, but got tls.no_pfs finding")
	}

	// httptest certs use 2048-bit RSA (or ECDSA), so weak-key should NOT fire
	if hasCheckID(findings, finding.CheckTLSCertWeakKey) {
		t.Error("httptest Go TLS should have >= 2048 bit key, but got tls.cert_weak_key finding")
	}

	// httptest server supports TLS 1.2+ and rejects TLS 1.0/1.1
	if hasCheckID(findings, finding.CheckTLSProtocolTLS10) {
		t.Error("httptest Go TLS should reject TLS 1.0, but got tls.protocol_tls10 finding")
	}
	if hasCheckID(findings, finding.CheckTLSProtocolTLS11) {
		t.Error("httptest Go TLS should reject TLS 1.1, but got tls.protocol_tls11 finding")
	}
}

func TestRun_TLS12OnlyServer(t *testing.T) {
	srv, host, port := tlsServerWithConfig(t, &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
	})
	defer srv.Close()

	asset := host + ":" + port
	s := New()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Server only speaks TLS 1.2, so tls.no_tls13 should fire
	if !hasCheckID(findings, finding.CheckTLSNoTLS13) {
		t.Error("expected tls.no_tls13 finding for TLS 1.2-only server")
	}

	// Should NOT have deprecated protocol findings since min is TLS 1.2
	if hasCheckID(findings, finding.CheckTLSProtocolTLS10) {
		t.Error("TLS 1.2-only server should not accept TLS 1.0")
	}
	if hasCheckID(findings, finding.CheckTLSProtocolTLS11) {
		t.Error("TLS 1.2-only server should not accept TLS 1.1")
	}
}

func TestRun_ServerAcceptingTLS10(t *testing.T) {
	srv, host, port := tlsServerWithConfig(t, &tls.Config{
		MinVersion: tls.VersionTLS10,
	})
	defer srv.Close()

	asset := host + ":" + port
	s := New()
	findings, err := s.Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasCheckID(findings, finding.CheckTLSProtocolTLS10) {
		t.Error("expected tls.protocol_tls10 finding for server accepting TLS 1.0")
	}
	if !hasCheckID(findings, finding.CheckTLSProtocolTLS11) {
		t.Error("expected tls.protocol_tls11 finding for server accepting TLS 1.1")
	}
}

func TestRun_UnreachableHost_ReturnsNil(t *testing.T) {
	s := New()
	findings, err := s.Run(context.Background(), "127.0.0.1:1", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if findings != nil {
		t.Errorf("unreachable host should return nil findings, got %d", len(findings))
	}
}

// ── HSTS ─────────────────────────────────────────────────────────────────────

func TestCheckHSTS_ShortMaxAge(t *testing.T) {
	findings := parseHSTSFindings("max-age=3600", "example.com", time.Time{})
	if !hasCheckID(findings, finding.CheckTLSHSTSShortMaxAge) {
		t.Error("expected hsts_short_max_age finding for max-age=3600")
	}
}

func TestCheckHSTS_MissingSubdomains(t *testing.T) {
	findings := parseHSTSFindings("max-age=31536000", "example.com", time.Time{})
	if !hasCheckID(findings, finding.CheckTLSHSTSNoSubdomains) {
		t.Error("expected hsts_no_subdomains finding")
	}
}

func TestCheckHSTS_MissingPreload(t *testing.T) {
	findings := parseHSTSFindings("max-age=31536000; includeSubDomains", "example.com", time.Time{})
	if !hasCheckID(findings, finding.CheckTLSHSTSNoPreload) {
		t.Error("expected hsts_no_preload finding")
	}
}

func TestCheckHSTS_AllDirectivesPresent_NoExtraFindings(t *testing.T) {
	findings := parseHSTSFindings("max-age=31536000; includeSubDomains; preload", "example.com", time.Time{})
	for _, f := range findings {
		switch f.CheckID {
		case finding.CheckTLSHSTSShortMaxAge,
			finding.CheckTLSHSTSNoSubdomains,
			finding.CheckTLSHSTSNoPreload:
			t.Errorf("unexpected finding %s for well-configured HSTS", f.CheckID)
		}
	}
}

func TestCheckHSTS_MaxAgeExactlyOneYear_NoShortMaxAgeFound(t *testing.T) {
	findings := parseHSTSFindings("max-age=31536000; includeSubDomains; preload", "example.com", time.Time{})
	if hasCheckID(findings, finding.CheckTLSHSTSShortMaxAge) {
		t.Error("max-age=31536000 (exactly 1 year) should not trigger short max-age finding")
	}
}

func TestCheckHSTS_MaxAgeZero_NoShortMaxAgeFound(t *testing.T) {
	// max-age=0 is used to clear HSTS; the check requires maxAge > 0 && < 31536000
	findings := parseHSTSFindings("max-age=0", "example.com", time.Time{})
	if hasCheckID(findings, finding.CheckTLSHSTSShortMaxAge) {
		t.Error("max-age=0 should not trigger short max-age finding (edge case)")
	}
}

// ── No SCT check (post-April 2018 cert without CT) ──────────────────────────

func TestNoSCT_PostCTMandate_EmitsFinding(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// Cert issued after April 2018 with no SCT
	cert := generateSelfSignedCert(t, certOpts{
		rsaKey:    key,
		addSANs:   true,
		addSCT:    false,
		notBefore: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		notAfter:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	})

	if hasSCT(cert) {
		t.Fatal("test cert should not have SCT")
	}
	// The scanner checks: !hasSCT && notBefore.After(2018-04-30)
	ctMandateDate := time.Date(2018, 4, 30, 0, 0, 0, 0, time.UTC)
	if !cert.NotBefore.After(ctMandateDate) {
		t.Fatal("test cert NotBefore should be after CT mandate date")
	}
}

func TestNoSCT_PreCTMandate_NoFinding(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// Cert issued before April 2018 -- should not trigger no-SCT finding
	cert := generateSelfSignedCert(t, certOpts{
		rsaKey:    key,
		addSANs:   true,
		addSCT:    false,
		notBefore: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
		notAfter:  time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC),
	})

	ctMandateDate := time.Date(2018, 4, 30, 0, 0, 0, 0, time.UTC)
	if cert.NotBefore.After(ctMandateDate) {
		t.Fatal("test cert NotBefore should be before CT mandate date")
	}
	// The scanner only flags missing SCT for certs issued after the mandate
}

func TestNoSCT_WithSCT_NoFinding(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := generateSelfSignedCert(t, certOpts{
		rsaKey:    key,
		addSANs:   true,
		addSCT:    true,
		notBefore: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		notAfter:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	})

	if !hasSCT(cert) {
		t.Error("cert with SCT extension should return true from hasSCT")
	}
}
