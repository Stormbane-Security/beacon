// Package grpcreflect detects gRPC servers with reflection enabled.
//
// gRPC server reflection exposes the complete service definition (all services,
// methods, and message types) to any client without authentication. This is
// equivalent to GraphQL introspection — it reveals the entire API surface.
//
// Detection uses a raw HTTP/2 POST to the reflection service endpoint. If the
// server responds with a valid gRPC reflection response, it confirms the service
// is available without authentication.
//
// Surface mode only — sends a single safe gRPC reflection list request.
package grpcreflect

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/http2"

	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)


func init() {
	scan.RegisterWithCheckDecls(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	},
		scan.Check(finding.CheckPortGRPCReflectionEnabled, finding.SeverityHigh, finding.ModeSurface),
	)
}
const scannerName = "grpcreflect"

// grpcPorts to probe for gRPC services.
var grpcPorts = []string{"50051", "9090", "443", "8443", "80", "8080"}

// reflectionPaths — the gRPC reflection service full method names.
var reflectionPaths = []string{
	"/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
	"/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
}

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanSurface && scanType != module.ScanDeep && scanType != module.ScanAuthorized {
		return nil, nil
	}

	host := asset
	assetPort := ""
	if h, p, err := net.SplitHostPort(asset); err == nil {
		host = h
		assetPort = p
	}

	// Build port list: asset's explicit port first, then defaults.
	ports := make([]string, 0, len(grpcPorts)+1)
	if assetPort != "" {
		ports = append(ports, assetPort)
	}
	for _, p := range grpcPorts {
		if p != assetPort {
			ports = append(ports, p)
		}
	}

	var findings []finding.Finding

	for _, port := range ports {
		if ctx.Err() != nil {
			break
		}

		addr := net.JoinHostPort(host, port)

		// Quick TCP check.
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			continue
		}
		_ = conn.Close()

		// Try gRPC reflection via HTTP/2.
		for _, reflPath := range reflectionPaths {
			if ctx.Err() != nil {
				break
			}

			services := probeReflection(ctx, host, port, reflPath)
			if len(services) > 0 {
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckPortGRPCReflectionEnabled,
					Module:   "surface",
					Scanner:  scannerName,
					Severity: finding.SeverityHigh,
					Title:    fmt.Sprintf("gRPC server reflection enabled on %s:%s — %d services exposed", host, port, len(services)),
					Description: fmt.Sprintf(
						"The gRPC server at %s:%s has reflection enabled, exposing %d service(s): %s. "+
							"Reflection allows any client to enumerate all available RPC methods, message "+
							"types, and field names without authentication — equivalent to GraphQL "+
							"introspection. Disable reflection in production or restrict access.",
						host, port, len(services), strings.Join(services, ", ")),
					Asset: asset,
					ProofCommand: fmt.Sprintf(
						"grpcurl -plaintext %s:%s list", host, port),
					Evidence: map[string]any{
						"host":     host,
						"port":     port,
						"services": services,
					},
					DiscoveredAt: time.Now(),
				})
				break // one finding per port
			}
		}
	}

	return findings, nil
}

// probeReflection sends a gRPC reflection ListServices request via HTTP/2.
func probeReflection(ctx context.Context, host, port, path string) []string {
	// Build a minimal gRPC reflection ListServices request.
	// ServerReflectionRequest.list_services is field 7, wire type 2 (length-delimited).
	// Tag = (7 << 3) | 2 = 0x3a, value = "" (length 0).
	protoMsg := []byte{0x3a, 0x00}

	// gRPC frame: 1 byte compression flag (0) + 4 bytes message length + message
	var grpcFrame bytes.Buffer
	grpcFrame.WriteByte(0x00) // no compression
	msgLen := make([]byte, 4)
	binary.BigEndian.PutUint32(msgLen, uint32(len(protoMsg)))
	grpcFrame.Write(msgLen)
	grpcFrame.Write(protoMsg)

	// Try both plaintext (h2c) and TLS.
	for _, useTLS := range []bool{false, true} {
		scheme := "http"
		var transport http.RoundTripper
		if useTLS {
			scheme = "https"
			transport = &http.Transport{
				ForceAttemptHTTP2: true,
				DialContext:       (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			}
		} else {
			// Plaintext HTTP/2 (h2c) — Go's standard http.Transport only
			// speaks HTTP/2 over TLS. For plaintext gRPC we need an
			// explicit HTTP/2 transport.
			transport = &http2.Transport{
				AllowHTTP: true,
				DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
					return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, addr)
				},
			}
		}

		client := &http.Client{
			Timeout:   8 * time.Second,
			Transport: transport,
		}

		url := fmt.Sprintf("%s://%s:%s%s", scheme, host, port, path)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url,
			bytes.NewReader(grpcFrame.Bytes()))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/grpc")
		req.Header.Set("TE", "trailers")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		_ = resp.Body.Close()

		ct := resp.Header.Get("Content-Type")
		if !strings.Contains(ct, "grpc") {
			continue
		}

		// Parse service names from the response body. Services appear as
		// length-prefixed strings in the protobuf response. We'll do a simple
		// scan for printable service name patterns (e.g., "com.example.Service").
		services := extractServiceNames(body)
		if len(services) > 0 {
			return services
		}
	}

	return nil
}

// extractServiceNames scans gRPC reflection response bytes for service names.
// Service names appear as length-prefixed strings containing dots (package.Service).
func extractServiceNames(data []byte) []string {
	var services []string
	seen := make(map[string]bool)

	for i := 0; i < len(data)-2; i++ {
		// Look for length-prefixed strings (field tag + length + ASCII chars).
		length := int(data[i])
		if length < 3 || length > 200 || i+1+length > len(data) {
			continue
		}

		candidate := string(data[i+1 : i+1+length])

		// Service names contain dots and only printable ASCII.
		if !strings.Contains(candidate, ".") {
			continue
		}
		valid := true
		for _, c := range candidate {
			if c < 0x20 || c > 0x7e {
				valid = false
				break
			}
		}
		if !valid || seen[candidate] {
			continue
		}

		// Filter out common non-service strings.
		if strings.HasPrefix(candidate, "grpc.reflection.") {
			continue
		}

		seen[candidate] = true
		services = append(services, candidate)
	}

	return services
}
