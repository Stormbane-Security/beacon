// Package favicon detects known services by computing MMH3 hashes of
// favicon.ico and matching against a database of known service fingerprints.
// This technique (popularized by Shodan) identifies services running on
// non-standard ports or behind reverse proxies.
package favicon

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"net/http"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scan"
)

func init() {
	scan.Register(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	})
}

const scannerName = "favicon"

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

// knownFavicons maps MMH3 hash → service name.
// Hashes computed as: mmh3(base64(favicon_bytes)) — Shodan convention.
var knownFavicons = map[int32]string{
	116323821:   "Fortinet FortiGate",
	-247388890:  "Apache Tomcat",
	988422585:   "Grafana",
	-305179312:  "Atlassian Jira",
	-1507567067: "Jenkins",
	81586312:    "Apache httpd (default)",
	-335242539:  "VMware Horizon",
	-1293291225: "SonarQube",
	1485257654:  "Zimbra",
	-1616143106: "Kibana",
	-1840324437: "Prometheus",
	442749392:   "Kubernetes Dashboard",
	1141356225:  "Gitea",
	735598661:   "GitLab",
	-1320900491: "Nextcloud",
	-1003740189: "Synology DSM",
	1550805029:  "pfSense",
	-1020586789: "UniFi Controller",
	266716421:   "Elastic HQ",
	-1321072987: "Rancher",
	-2057558656: "Portainer",
	1447830463:  "Traefik",
	-244067698:  "Minio Console",
	-857974680:  "HashiCorp Vault",
	-1380874553: "Spring Boot (default)",
	1354032249:  "Webmin",
	-1090592854: "OpenVPN Access Server",
	-1399433489: "Netdata",
	1967017233:  "Keycloak",
}

func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	paths := []string{"/favicon.ico", "/static/favicon.ico", "/assets/favicon.ico"}
	var findings []finding.Finding

	for _, scheme := range []string{"https", "http"} {
		for _, path := range paths {
			url := scheme + "://" + asset + path
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				continue
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB max
			resp.Body.Close()

			if resp.StatusCode != 200 || len(body) < 10 {
				continue
			}

			faviconHash := mmh3Hash(body)
			if service, ok := knownFavicons[faviconHash]; ok {
				md5sum := fmt.Sprintf("%x", md5.Sum(body))
				findings = append(findings, finding.Finding{
					CheckID:  finding.CheckFaviconHashMatch,
					Module:   "surface",
					Scanner:  scannerName,
					Severity: finding.SeverityInfo,
					Asset:    asset,
					Title:    fmt.Sprintf("Favicon identifies %s on %s", service, asset),
					Description: fmt.Sprintf(
						"The favicon at %s has MMH3 hash %d, matching %s. "+
							"This fingerprints the service even on non-standard ports or behind proxies.",
						url, faviconHash, service,
					),
					Evidence: map[string]any{
						"url":          url,
						"mmh3_hash":    faviconHash,
						"md5":          md5sum,
						"service":      service,
						"favicon_size": len(body),
					},
					ProofCommand: fmt.Sprintf("curl -s '%s' | md5", url),
					DiscoveredAt: time.Now(),
				})
				return findings, nil // One match is enough.
			}
		}
	}

	return findings, nil
}

// mmh3Hash computes the MurmurHash3 of base64-encoded favicon data.
// This matches Shodan's favicon hash computation.
func mmh3Hash(data []byte) int32 {
	b64 := base64.StdEncoding.EncodeToString(data)
	return murmur3_32([]byte(b64), 0)
}

// murmur3_32 implements MurmurHash3 x86_32.
func murmur3_32(data []byte, seed uint32) int32 {
	_ = hash.Hash32(nil) // interface compliance check at compile time — unused

	const (
		c1 = 0xcc9e2d51
		c2 = 0x1b873593
	)

	h := seed
	length := len(data)
	nblocks := length / 4

	for i := 0; i < nblocks; i++ {
		k := uint32(data[i*4]) | uint32(data[i*4+1])<<8 | uint32(data[i*4+2])<<16 | uint32(data[i*4+3])<<24
		k *= c1
		k = (k << 15) | (k >> 17)
		k *= c2
		h ^= k
		h = (h << 13) | (h >> 19)
		h = h*5 + 0xe6546b64
	}

	tail := data[nblocks*4:]
	var k1 uint32
	switch len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h ^= k1
	}

	h ^= uint32(length)
	// fmix32
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16

	return int32(h)
}
