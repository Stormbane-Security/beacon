// Package ntlm detects NTLM authentication info leaks. When a server
// supports NTLM/Negotiate auth, sending a Type 1 (Negotiate) message
// triggers a Type 2 (Challenge) response that leaks internal domain name,
// server name, DNS forest name, and OS version.
package ntlm

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan"
)

func init() {
	scan.Register(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	})
}

const scannerName = "ntlm"

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

// candidatePaths are endpoints that commonly support NTLM authentication.
var candidatePaths = []string{
	"/", "/ews/", "/rpc/", "/autodiscover/",
	"/OAB/", "/Microsoft-Server-ActiveSync/",
	"/api/", "/remote/", "/rdweb/",
}

// ntlmNegotiateMsg is a minimal NTLM Type 1 (Negotiate) message.
// Flags: NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_REQUEST_TARGET | NTLMSSP_NEGOTIATE_NTLM
var ntlmNegotiateMsg = base64.StdEncoding.EncodeToString([]byte{
	'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00, // Signature
	0x01, 0x00, 0x00, 0x00, // Type 1
	0x07, 0x82, 0x08, 0x00, // Flags
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Domain (empty)
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Workstation (empty)
})

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var findings []finding.Finding

	for _, path := range candidatePaths {
		for _, scheme := range []string{"https", "http"} {
			url := scheme + "://" + asset + path

			// First check if endpoint supports NTLM.
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				continue
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			io.Copy(io.Discard, io.LimitReader(resp.Body, 512))
			resp.Body.Close()

			if resp.StatusCode != 401 {
				continue
			}

			wwwAuth := resp.Header.Get("WWW-Authenticate")
			if !strings.Contains(strings.ToLower(wwwAuth), "ntlm") && !strings.Contains(strings.ToLower(wwwAuth), "negotiate") {
				continue
			}

			// Send NTLM Type 1 message to get Type 2 response.
			req2, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				continue
			}
			req2.Header.Set("Authorization", "NTLM "+ntlmNegotiateMsg)

			resp2, err := client.Do(req2)
			if err != nil {
				continue
			}
			io.Copy(io.Discard, io.LimitReader(resp2.Body, 512))
			resp2.Body.Close()

			// Parse Type 2 challenge from WWW-Authenticate header.
			auth := resp2.Header.Get("WWW-Authenticate")
			if !strings.HasPrefix(auth, "NTLM ") {
				continue
			}

			type2Data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "NTLM "))
			if err != nil || len(type2Data) < 32 {
				continue
			}

			info := parseType2(type2Data)
			if info == nil {
				continue
			}

			findings = append(findings, finding.Finding{
				CheckID:  finding.CheckNTLMInfoLeak,
				Module:   "surface",
				Scanner:  scannerName,
				Severity: finding.SeverityMedium,
				Asset:    asset,
				Title:    fmt.Sprintf("NTLM info leak at %s on %s", path, asset),
				Description: fmt.Sprintf(
					"The server at %s supports NTLM authentication and leaks internal information "+
						"in the Type 2 challenge response. Domain: %q, Server: %q, DNS Domain: %q. "+
						"This information assists attackers in mapping internal Active Directory infrastructure.",
					url, info["domain"], info["server"], info["dns_domain"],
				),
				Evidence: info,
				ProofCommand: fmt.Sprintf(
					"curl -sI -H 'Authorization: NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAo=' '%s' | grep -i www-authenticate",
					url),
				DiscoveredAt: time.Now(),
			})
			return findings, nil // One leak is enough per asset.
		}
	}

	return findings, nil
}

// parseType2 extracts target info fields from an NTLM Type 2 message.
func parseType2(data []byte) map[string]any {
	// Verify NTLMSSP signature and Type 2 marker.
	if len(data) < 32 || string(data[:7]) != "NTLMSSP" || data[8] != 0x02 {
		return nil
	}

	info := map[string]any{}

	// Target name at offset 12 (length at 12, offset at 16).
	if len(data) >= 20 {
		targetLen := int(binary.LittleEndian.Uint16(data[12:14]))
		targetOff := int(binary.LittleEndian.Uint32(data[16:20]))
		if targetOff+targetLen <= len(data) {
			info["domain"] = decodeUTF16LE(data[targetOff : targetOff+targetLen])
		}
	}

	// Target info pairs at offset indicated by bytes 40-43 (length at 40, offset at 44).
	if len(data) >= 48 {
		tiLen := int(binary.LittleEndian.Uint16(data[40:42]))
		tiOff := int(binary.LittleEndian.Uint32(data[44:48]))
		if tiOff+tiLen <= len(data) {
			parseTargetInfo(data[tiOff:tiOff+tiLen], info)
		}
	}

	if len(info) == 0 {
		return nil
	}
	return info
}

func parseTargetInfo(data []byte, info map[string]any) {
	for len(data) >= 4 {
		avID := binary.LittleEndian.Uint16(data[0:2])
		avLen := int(binary.LittleEndian.Uint16(data[2:4]))
		if avLen+4 > len(data) {
			break
		}
		value := decodeUTF16LE(data[4 : 4+avLen])

		switch avID {
		case 0x0000: // MsvAvEOL
			return
		case 0x0001: // MsvAvNbComputerName
			info["server"] = value
		case 0x0002: // MsvAvNbDomainName
			info["domain"] = value
		case 0x0003: // MsvAvDnsDomainName
			info["dns_domain"] = value
		case 0x0004: // MsvAvDnsComputerName
			info["dns_server"] = value
		case 0x0005: // MsvAvDnsTreeName
			info["dns_forest"] = value
		}

		data = data[4+avLen:]
	}
}

func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		return string(b)
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u16))
}
