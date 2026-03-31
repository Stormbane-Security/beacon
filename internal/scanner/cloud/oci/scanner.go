// Package oci implements authenticated Oracle Cloud Infrastructure (OCI) security
// scanning. It uses the OCI REST API directly with request signing (no SDK
// dependency). All API calls are read-only.
//
// Authentication uses the standard OCI configuration file (~/.oci/config) which
// contains the tenancy OCID, user OCID, key fingerprint, and private key path.
package oci

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

const (
	maxBody    = 10 << 20 // 10 MiB limit on response bodies
	scannerTag = "cloud/oci"
)

// Config holds OCI authentication configuration.
type Config struct {
	// ConfigFile is the path to the OCI configuration file.
	// Defaults to ~/.oci/config if empty.
	ConfigFile string
}

// ociConfig holds parsed OCI configuration values.
type ociConfig struct {
	Tenancy     string
	User        string
	Region      string
	Fingerprint string
	KeyFile     string
	privateKey  *rsa.PrivateKey
}

// Scanner runs authenticated OCI security checks.
type Scanner struct {
	cfg    Config
	client *http.Client
}

// New creates a new OCI cloud scanner.
func New(cfg Config) *Scanner {
	return &Scanner{
		cfg: cfg,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return scannerTag }

// Run implements scanner.Scanner.
// asset is the root domain being scanned -- used only for finding attribution.
func (s *Scanner) Run(ctx context.Context, asset string, _ module.ScanType) ([]finding.Finding, error) {
	ociCfg, err := s.loadConfig()
	if err != nil {
		return nil, fmt.Errorf("oci: load config: %w", err)
	}

	var all []finding.Finding

	// Object Storage checks.
	osFindings, err := scanObjectStorage(ctx, s, ociCfg, asset)
	if err != nil {
		all = append(all, scanError(asset, fmt.Sprintf("Object Storage scan failed: %v", err)))
	} else {
		all = append(all, osFindings...)
	}

	// Network security checks (security lists and NSGs).
	netFindings, err := scanNetwork(ctx, s, ociCfg, asset)
	if err != nil {
		all = append(all, scanError(asset, fmt.Sprintf("Network scan failed: %v", err)))
	} else {
		all = append(all, netFindings...)
	}

	// Vault key rotation checks.
	vaultFindings, err := scanVault(ctx, s, ociCfg, asset)
	if err != nil {
		all = append(all, scanError(asset, fmt.Sprintf("Vault scan failed: %v", err)))
	} else {
		all = append(all, vaultFindings...)
	}

	return all, nil
}

// loadConfig parses the OCI configuration file.
func (s *Scanner) loadConfig() (*ociConfig, error) {
	path := s.cfg.ConfigFile
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("home dir: %w", err)
		}
		path = filepath.Join(home, ".oci", "config")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	cfg := &ociConfig{}
	section := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			continue
		}
		// Only parse the DEFAULT profile.
		if section != "DEFAULT" && section != "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "tenancy":
			cfg.Tenancy = val
		case "user":
			cfg.User = val
		case "region":
			cfg.Region = val
		case "fingerprint":
			cfg.Fingerprint = val
		case "key_file":
			// Expand ~ to home directory.
			if strings.HasPrefix(val, "~") {
				home, _ := os.UserHomeDir()
				val = filepath.Join(home, val[1:])
			}
			cfg.KeyFile = val
		}
	}

	if cfg.Tenancy == "" || cfg.User == "" || cfg.Region == "" || cfg.Fingerprint == "" || cfg.KeyFile == "" {
		return nil, fmt.Errorf("incomplete OCI config: need tenancy, user, region, fingerprint, key_file in %s", path)
	}

	// Load the private key.
	keyData, err := os.ReadFile(cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("read key %s: %w", cfg.KeyFile, err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", cfg.KeyFile)
	}

	privKey, err := parsePrivateKey(block)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	cfg.privateKey = privKey

	return cfg, nil
}

// parsePrivateKey tries PKCS8 first, then PKCS1.
func parsePrivateKey(block *pem.Block) (*rsa.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, fmt.Errorf("PKCS8 key is not RSA")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// doSignedRequest performs an OCI API request with request signing per
// https://docs.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm
func (s *Scanner) doSignedRequest(ctx context.Context, ociCfg *ociConfig, method, host, path string, dst any) error {
	url := "https://" + host + path
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	// Required headers for OCI signing.
	now := time.Now().UTC()
	req.Header.Set("date", now.Format(http.TimeFormat))
	req.Header.Set("host", host)
	req.Header.Set("content-type", "application/json")

	// Build the signing string.
	// For GET requests, sign: (request-target) date host
	signingHeaders := "(request-target) date host"
	requestTarget := strings.ToLower(method) + " " + path
	signingString := fmt.Sprintf("(request-target): %s\ndate: %s\nhost: %s",
		requestTarget,
		req.Header.Get("date"),
		host,
	)

	// Sign with RSA-SHA256.
	hash := sha256.Sum256([]byte(signingString))
	signature, err := rsa.SignPKCS1v15(nil, ociCfg.privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return fmt.Errorf("sign request: %w", err)
	}

	keyID := fmt.Sprintf("%s/%s/%s", ociCfg.Tenancy, ociCfg.User, ociCfg.Fingerprint)
	authHeader := fmt.Sprintf(
		`Signature version="1",keyId="%s",algorithm="rsa-sha256",headers="%s",signature="%s"`,
		keyID, signingHeaders, base64.StdEncoding.EncodeToString(signature),
	)
	req.Header.Set("authorization", authHeader)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API %s returned %d: %s", path, resp.StatusCode, truncate(string(body), 200))
	}

	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// objectStorageHost returns the Object Storage API host for the given region.
func objectStorageHost(region string) string {
	return fmt.Sprintf("objectstorage.%s.oraclecloud.com", region)
}

// identityHost returns the IAM/Identity API host for the given region.
func identityHost(region string) string {
	return fmt.Sprintf("identity.%s.oraclecloud.com", region)
}

// coreHost returns the Core Services (VCN, compute) API host for the given region.
func coreHost(region string) string {
	return fmt.Sprintf("iaas.%s.oraclecloud.com", region)
}

// kmsManagementHost returns the KMS management API host for the given vault endpoint.
func kmsManagementHost(vaultEndpoint string) string {
	// Vault management endpoint is typically: https://<vault-id>-management.kms.<region>.oraclecloud.com
	// We receive the full management endpoint URL and extract the host.
	vaultEndpoint = strings.TrimPrefix(vaultEndpoint, "https://")
	vaultEndpoint = strings.TrimPrefix(vaultEndpoint, "http://")
	if idx := strings.Index(vaultEndpoint, "/"); idx != -1 {
		vaultEndpoint = vaultEndpoint[:idx]
	}
	return vaultEndpoint
}

// scanError returns a scan-error finding for the OCI scanner.
func scanError(asset, description string) finding.Finding {
	return finding.Finding{
		CheckID:      finding.CheckCloudOCIScanError,
		Title:        "OCI scan error",
		Description:  description,
		Severity:     finding.SeverityInfo,
		Asset:        asset,
		Scanner:      scannerTag,
		DiscoveredAt: time.Now(),
	}
}

// truncate shortens s to at most maxLen characters.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
