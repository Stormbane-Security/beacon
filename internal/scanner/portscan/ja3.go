package portscan

import (
	"context"
	"crypto/md5" //nolint:gosec // JA3S uses MD5 by specification
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// JA3SResult captures a TLS server's JA3S-style fingerprint derived from
// the negotiated TLS parameters, plus certificate metadata.
type JA3SResult struct {
	Hash        string    // MD5 hex digest of RawString
	RawString   string    // "SSLVersion,Cipher,Extensions" before hashing
	TLSVersion  uint16    // e.g. 0x0303 = TLS 1.2, 0x0304 = TLS 1.3
	CipherSuite uint16    // negotiated cipher suite ID
	ServerName  string    // leaf certificate CN or first SAN
	SANs        []string  // all Subject Alternative Names
	Issuer      string    // certificate issuer organization
	NotBefore   time.Time // certificate validity start
	NotAfter    time.Time // certificate validity end
	KeyBits     int       // public key size in bits
}

// ja3sCache stores fingerprint results so we don't handshake twice (isTLSCapable
// already does one handshake per host:port). A nil *JA3SResult means the port
// doesn't speak TLS.
var (
	ja3sCache   = make(map[string]*JA3SResult)
	ja3sCacheMu sync.Mutex
)

// tlsVersionDecimal returns the decimal representation of a TLS version
// as used in the JA3S specification.
func tlsVersionDecimal(v uint16) string {
	return strconv.FormatUint(uint64(v), 10)
}

// ja3sHash computes the JA3S hash: MD5(SSLVersion,Cipher,Extensions).
// Since Go's crypto/tls does not expose raw ServerHello extensions,
// the extensions field is left empty — the Version+Cipher pair still
// produces a useful server fingerprint.
func ja3sHash(version, cipher uint16) (hash, raw string) {
	// JA3S format: SSLVersion,Cipher,Extensions
	raw = fmt.Sprintf("%s,%s,", tlsVersionDecimal(version), strconv.FormatUint(uint64(cipher), 10))
	sum := md5.Sum([]byte(raw)) //nolint:gosec
	hash = fmt.Sprintf("%x", sum)
	return hash, raw
}

// publicKeyBits returns the bit size of a certificate's public key.
func publicKeyBits(cert *x509.Certificate) int {
	if cert == nil {
		return 0
	}
	switch pub := cert.PublicKey.(type) {
	case interface{ Size() int }:
		// *rsa.PublicKey implements Size() returning bytes
		return pub.Size() * 8
	case interface{ Params() *struct{ BitSize int } }:
		_ = pub
		return 0
	default:
		// For ECDSA, Ed25519, etc. use the raw key bit length from x509
		if cert.PublicKeyAlgorithm == x509.ECDSA {
			// ECDSA keys: parse from the curve
			type ecKey interface {
				Params() interface{ BitSize() int }
			}
			// Fallback: estimate from signature algorithm
			switch {
			case strings.Contains(cert.SignatureAlgorithm.String(), "256"):
				return 256
			case strings.Contains(cert.SignatureAlgorithm.String(), "384"):
				return 384
			case strings.Contains(cert.SignatureAlgorithm.String(), "512"):
				return 521
			}
		}
		return 0
	}
}

// JA3SFingerprint performs a TLS handshake and extracts the JA3S-style
// fingerprint plus certificate metadata from the server at host:port.
// Returns nil if the port does not speak TLS.
func JA3SFingerprint(ctx context.Context, host string, port int) *JA3SResult {
	key := fmt.Sprintf("%s:%d", host, port)
	ja3sCacheMu.Lock()
	if res, ok := ja3sCache[key]; ok {
		ja3sCacheMu.Unlock()
		return res
	}
	ja3sCacheMu.Unlock()

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: 2 * time.Second}

	// Use a context-aware dial if the context has a deadline.
	if deadline, ok := ctx.Deadline(); ok {
		dialer.Deadline = deadline
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // scanning unknown hosts
	})
	if err != nil {
		ja3sCacheMu.Lock()
		ja3sCache[key] = nil
		ja3sCacheMu.Unlock()
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	hash, raw := ja3sHash(state.Version, state.CipherSuite)

	result := &JA3SResult{
		Hash:        hash,
		RawString:   raw,
		TLSVersion:  state.Version,
		CipherSuite: state.CipherSuite,
	}

	// Extract certificate metadata from the leaf cert.
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		result.ServerName = leaf.Subject.CommonName
		result.SANs = leaf.DNSNames
		if len(leaf.Issuer.Organization) > 0 {
			result.Issuer = leaf.Issuer.Organization[0]
		}
		result.NotBefore = leaf.NotBefore
		result.NotAfter = leaf.NotAfter
		result.KeyBits = publicKeyBits(leaf)
	}

	ja3sCacheMu.Lock()
	ja3sCache[key] = result
	ja3sCacheMu.Unlock()
	return result
}

// tlsVersionName returns a human-readable TLS version string.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionSSL30:
		return "SSL 3.0"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// cipherSuiteName returns the name of a cipher suite by ID.
func cipherSuiteName(id uint16) string {
	// Check standard suites first.
	for _, s := range tls.CipherSuites() {
		if s.ID == id {
			return s.Name
		}
	}
	// Check insecure suites.
	for _, s := range tls.InsecureCipherSuites() {
		if s.ID == id {
			return s.Name
		}
	}
	return fmt.Sprintf("0x%04X", id)
}

// isWeakCipherSuite returns true if the cipher suite is considered weak.
// A cipher is weak if it appears in Go's InsecureCipherSuites() list or
// uses known-broken primitives (RC4, DES, 3DES, NULL, export).
func isWeakCipherSuite(id uint16) bool {
	for _, s := range tls.InsecureCipherSuites() {
		if s.ID == id {
			return true
		}
	}
	return false
}

// TLSInfoEvidence returns a map of TLS metadata suitable for inclusion
// in a finding's Evidence field.
func TLSInfoEvidence(r *JA3SResult) map[string]any {
	if r == nil {
		return nil
	}
	ev := map[string]any{
		"ja3s_hash":       r.Hash,
		"ja3s_raw":        r.RawString,
		"tls_version":     tlsVersionName(r.TLSVersion),
		"cipher_suite":    cipherSuiteName(r.CipherSuite),
		"cipher_suite_id": r.CipherSuite,
	}
	if r.ServerName != "" {
		ev["cert_cn"] = r.ServerName
	}
	if len(r.SANs) > 0 {
		ev["cert_sans"] = r.SANs
	}
	if r.Issuer != "" {
		ev["cert_issuer"] = r.Issuer
	}
	if !r.NotAfter.IsZero() {
		ev["cert_not_after"] = r.NotAfter.Format(time.RFC3339)
	}
	if !r.NotBefore.IsZero() {
		ev["cert_not_before"] = r.NotBefore.Format(time.RFC3339)
	}
	if r.KeyBits > 0 {
		ev["cert_key_bits"] = r.KeyBits
	}
	return ev
}
