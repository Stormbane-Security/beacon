package classify

// JARM TLS fingerprinting — sends multiple custom TLS ClientHello messages and
// fingerprints the server based on which cipher suite it selects and the TLS
// version it echoes back. Different TLS stacks (nginx, Apache httpd, IIS, Cloudflare,
// Fastly, AWS ALB, etc.) produce distinct fingerprints even when Server: headers
// are stripped.
//
// This implementation sends 4 probes (vs. Salesforce JARM's 10) covering the
// most discriminating variations: forward cipher order, reverse cipher order,
// forward with ALPN, and TLS 1.3 ciphers. The resulting 32-char hex hash is
// NOT byte-for-byte Shodan-compatible but is stable and internally consistent
// for grouping servers across assets.

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/playbook"
)

// jarmCiphers12 is the forward cipher list for TLS 1.2 probes.
// Mirrors the Salesforce JARM reference cipher set.
var jarmCiphers12 = []uint16{
	0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
	0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
	0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
	0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
	0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
	0x009c, // TLS_RSA_WITH_AES_128_GCM_SHA256
	0x009d, // TLS_RSA_WITH_AES_256_GCM_SHA384
	0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
	0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
	0x000a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
}

// jarmCiphers13 is the TLS 1.3 cipher list for probe 4.
var jarmCiphers13 = []uint16{
	0x1301, // TLS_AES_128_GCM_SHA256
	0x1302, // TLS_AES_256_GCM_SHA384
	0x1303, // TLS_CHACHA20_POLY1305_SHA256
}

type jarmProbeConfig struct {
	ciphers []uint16
	version uint16   // ClientHello legacy_version
	alpns   []string // ALPN protocols to offer (nil = omit extension)
}

// jarmFingerprint sends 4 custom TLS ClientHellos to hostname:443 and returns
// a 32-char hex fingerprint derived from the server responses. Returns "" if
// all probes fail (no TLS on port 443 or connection refused).
func jarmFingerprint(ctx context.Context, hostname string) string {
	probes := []jarmProbeConfig{
		{ciphers: jarmCiphers12, version: 0x0303, alpns: nil},
		{ciphers: reverseUint16(jarmCiphers12), version: 0x0303, alpns: nil},
		{ciphers: jarmCiphers12, version: 0x0303, alpns: []string{"h2", "http/1.1"}},
		{ciphers: jarmCiphers13, version: 0x0303, alpns: []string{"h2"}},
	}

	var parts []string
	anyResponse := false
	for _, p := range probes {
		cipher, version := sendJARMProbe(ctx, hostname, p)
		if cipher != 0 || version != 0 {
			anyResponse = true
		}
		parts = append(parts, fmt.Sprintf("%04x%04x", cipher, version))
	}

	if !anyResponse {
		return ""
	}

	raw := strings.Join(parts, "|")
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", h[:16])
}

// sendJARMProbe connects to hostname:443, sends a crafted ClientHello, reads
// the ServerHello, and returns the chosen cipher and server version.
// Returns (0, 0) on any error.
func sendJARMProbe(ctx context.Context, hostname string, p jarmProbeConfig) (cipher, version uint16) {
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Honour port-specific assets (e.g. "api.example.com:8443"). When no port
	// is present in hostname, default to 443.
	addr := hostname
	if _, _, err := net.SplitHostPort(hostname); err != nil {
		addr = hostname + ":443"
	}

	// Extract bare hostname for SNI (must not include port).
	sniHost := hostname
	if h, _, err := net.SplitHostPort(hostname); err == nil {
		sniHost = h
	}

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return 0, 0
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	hello := buildJARMHello(sniHost, p.ciphers, p.version, p.alpns)
	if _, err := conn.Write(hello); err != nil {
		return 0, 0
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 11 {
		return 0, 0
	}

	return parseJARMServerHello(buf[:n])
}

// buildJARMHello constructs a raw TLS ClientHello record for JARM probing.
// The record is a standard TLS 1.2 ClientHello with configurable cipher list
// and optional ALPN extension. It does NOT complete a TLS handshake.
func buildJARMHello(hostname string, ciphers []uint16, helloVersion uint16, alpns []string) []byte {
	// Build extensions
	var exts []byte
	exts = append(exts, buildSNIExtension(hostname)...)
	exts = append(exts, buildSupportedGroupsExtension()...)
	exts = append(exts, buildECPointFormatsExtension()...)
	if len(alpns) > 0 {
		exts = append(exts, buildALPNExtension(alpns)...)
	}

	// ClientHello body
	var body []byte
	body = appendUint16BE(body, helloVersion)
	body = append(body, make([]byte, 32)...) // random: 32 zero bytes
	body = append(body, 0)                   // session ID length: 0 (empty)

	cipherBytes := make([]byte, len(ciphers)*2)
	for i, c := range ciphers {
		binary.BigEndian.PutUint16(cipherBytes[i*2:], c)
	}
	body = appendUint16BE(body, uint16(len(cipherBytes)))
	body = append(body, cipherBytes...)

	body = append(body, 1, 0) // compression methods length=1, null compression

	body = appendUint16BE(body, uint16(len(exts)))
	body = append(body, exts...)

	// Handshake message: type(1) + length(3) + body
	var hs []byte
	hs = append(hs, 0x01) // ClientHello
	hs = appendUint24BE(hs, uint32(len(body)))
	hs = append(hs, body...)

	// TLS record: content_type(1) + legacy_version(2) + length(2) + handshake
	var record []byte
	record = append(record, 0x16)               // Handshake
	record = appendUint16BE(record, 0x0301)     // legacy record version: TLS 1.0
	record = appendUint16BE(record, uint16(len(hs)))
	record = append(record, hs...)
	return record
}

func buildSNIExtension(hostname string) []byte {
	name := []byte(hostname)
	// server_name_list entry: name_type(1) + name_length(2) + name
	entry := make([]byte, 3+len(name))
	entry[0] = 0x00 // host_name type
	binary.BigEndian.PutUint16(entry[1:], uint16(len(name)))
	copy(entry[3:], name)
	// extension: type(2) + data_length(2) + list_length(2) + entry
	var ext []byte
	ext = appendUint16BE(ext, 0x0000) // SNI
	listLen := appendUint16BE(nil, uint16(len(entry)))
	listLen = append(listLen, entry...)
	ext = appendUint16BE(ext, uint16(len(listLen)))
	ext = append(ext, listLen...)
	return ext
}

func buildALPNExtension(protocols []string) []byte {
	var protoList []byte
	for _, p := range protocols {
		protoList = append(protoList, byte(len(p)))
		protoList = append(protoList, p...)
	}
	// extension: type(2) + data_length(2) + list_length(2) + protocols
	var ext []byte
	ext = appendUint16BE(ext, 0x0010) // ALPN
	data := appendUint16BE(nil, uint16(len(protoList)))
	data = append(data, protoList...)
	ext = appendUint16BE(ext, uint16(len(data)))
	ext = append(ext, data...)
	return ext
}

func buildSupportedGroupsExtension() []byte {
	groups := []uint16{0x001d, 0x0017, 0x0018} // x25519, secp256r1, secp384r1
	groupBytes := make([]byte, len(groups)*2)
	for i, g := range groups {
		binary.BigEndian.PutUint16(groupBytes[i*2:], g)
	}
	var ext []byte
	ext = appendUint16BE(ext, 0x000a) // supported_groups
	data := appendUint16BE(nil, uint16(len(groupBytes)))
	data = append(data, groupBytes...)
	ext = appendUint16BE(ext, uint16(len(data)))
	ext = append(ext, data...)
	return ext
}

func buildECPointFormatsExtension() []byte {
	var ext []byte
	ext = appendUint16BE(ext, 0x000b) // ec_point_formats
	ext = appendUint16BE(ext, 2)      // data length
	ext = append(ext, 1, 0x00)        // list length=1, uncompressed
	return ext
}

// parseJARMServerHello extracts the chosen cipher suite and server version from
// a TLS ServerHello record. Returns (0, 0) if the data is too short or not a ServerHello.
//
// ServerHello structure (offset from start of data):
//   0x16 (1)       — record content type: Handshake
//   version (2)    — record layer version (ignored)
//   length (2)     — record layer length (ignored)
//   0x02 (1)       — handshake type: ServerHello
//   length (3)     — handshake body length (ignored)
//   version (2)    — server version  ← want this
//   random (32)    — server random
//   sid_len (1)    — session ID length
//   sid (sid_len)  — session ID
//   cipher (2)     — chosen cipher suite  ← want this
func parseJARMServerHello(data []byte) (cipher, version uint16) {
	// Record header: type(1) + version(2) + length(2) = 5 bytes
	if len(data) < 9 || data[0] != 0x16 {
		return 0, 0
	}
	// Handshake header starts at offset 5: type(1) + length(3)
	if data[5] != 0x02 { // not ServerHello
		return 0, 0
	}
	// ServerHello body starts at offset 9
	const bodyStart = 9
	if len(data) < bodyStart+35 { // version(2) + random(32) + sid_len(1)
		return 0, 0
	}
	version = binary.BigEndian.Uint16(data[bodyStart:])
	sidLen := int(data[bodyStart+34])
	cipherOff := bodyStart + 35 + sidLen
	if len(data) < cipherOff+2 {
		return version, 0
	}
	cipher = binary.BigEndian.Uint16(data[cipherOff:])
	return cipher, version
}

// reverseUint16 returns a reversed copy of s.
func reverseUint16(s []uint16) []uint16 {
	r := make([]uint16, len(s))
	copy(r, s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return r
}

// appendUint16BE appends a big-endian uint16 to b.
func appendUint16BE(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

// appendUint24BE appends a big-endian uint24 to b.
func appendUint24BE(b []byte, v uint32) []byte {
	return append(b, byte(v>>16), byte(v>>8), byte(v))
}

// EmitJARMFinding returns an info finding with the JARM TLS fingerprint for
// the asset, or nil if no fingerprint was collected. This finding gives the
// AI enricher server-family context even when banners are stripped.
func EmitJARMFinding(ev playbook.Evidence, asset string) *finding.Finding {
	if ev.JARMFingerprint == "" {
		return nil
	}
	f := finding.Finding{
		CheckID:  finding.CheckTLSJARM,
		Module:   "surface",
		Scanner:  "classify",
		Severity: finding.SeverityInfo,
		Asset:    asset,
		Title:    fmt.Sprintf("JARM TLS fingerprint: %s", ev.JARMFingerprint),
		Description: fmt.Sprintf(
			"The TLS server at %s responded to custom ClientHello probes with fingerprint %s. "+
				"This fingerprint identifies the TLS implementation (e.g. nginx, Apache, IIS, CDN edge) "+
				"independently of Server: headers, enabling server-family detection for assets that strip version banners.",
			asset, ev.JARMFingerprint),
		Evidence:     map[string]any{"jarm": ev.JARMFingerprint},
		DiscoveredAt: time.Now(),
	}
	return &f
}
