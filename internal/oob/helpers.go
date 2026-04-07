package oob

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// PayloadURL returns the full HTTP callback URL for the given token.
// Scanners inject this into blind SSRF, blind XXE, and similar payloads.
func PayloadURL(srv *Server, token string) string {
	return srv.CallbackURL(token)
}

// PayloadDNS returns the DNS hostname for the given token.
// Scanners inject this into blind command-injection or SSRF payloads that
// trigger a DNS lookup (e.g., nslookup <host>, curl http://<host>).
func PayloadDNS(srv *Server, token string) string {
	return srv.DNSHostname(token)
}

// MakeToken is a convenience that generates a structured token label from
// scanner name, asset, and probe identifier, then calls GenerateToken.
// The label format is "<scanner>-<asset-hash>-<probe>" which allows
// correlating which probe triggered which callback.
func MakeToken(srv *Server, scanner, asset, probe string) string {
	h := sha256.Sum256([]byte(asset))
	assetHash := hex.EncodeToString(h[:4]) // 8 hex chars
	label := fmt.Sprintf("%s-%s-%s", scanner, assetHash, probe)
	return srv.GenerateToken(label)
}

// TokenLabel returns the label associated with a token, or "" if unknown.
func TokenLabel(srv *Server, token string) string {
	srv.mu.RLock()
	defer srv.mu.RUnlock()
	return srv.tokens[token]
}
