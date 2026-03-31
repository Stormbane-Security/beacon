package oci

import (
	"context"
	"fmt"
	"time"

	"github.com/stormbane/beacon/internal/finding"
)

// namespaceResponse is the API response for getting the Object Storage namespace.
type namespaceResponse string

// bucketListResponse is the API response for listing buckets.
type bucketSummary struct {
	Name          string `json:"name"`
	Namespace     string `json:"namespace"`
	CompartmentID string `json:"compartmentId"`
	CreatedBy     string `json:"createdBy"`
	TimeCreated   string `json:"timeCreated"`
}

// bucketDetail is the API response for getting bucket details.
type bucketDetail struct {
	Name                string `json:"name"`
	Namespace           string `json:"namespace"`
	CompartmentID       string `json:"compartmentId"`
	PublicAccessType    string `json:"publicAccessType"`    // NoPublicAccess, ObjectRead, ObjectReadWithoutList
	KmsKeyID            string `json:"kmsKeyId"`            // empty = Oracle-managed encryption only
	IsReadOnly          bool   `json:"isReadOnly"`
	ObjectEventsEnabled bool   `json:"objectEventsEnabled"`
	Versioning          string `json:"versioning"`          // Disabled, Enabled, Suspended
}

// scanObjectStorage checks OCI Object Storage buckets for public access and encryption.
func scanObjectStorage(ctx context.Context, s *Scanner, cfg *ociConfig, asset string) ([]finding.Finding, error) {
	host := objectStorageHost(cfg.Region)

	// Get the namespace (required for all Object Storage operations).
	var namespace string
	if err := s.doSignedRequest(ctx, cfg, "GET", host, "/n/", &namespace); err != nil {
		return nil, fmt.Errorf("get namespace: %w", err)
	}

	// List buckets in the root compartment (tenancy).
	compartmentID := cfg.Tenancy
	path := fmt.Sprintf("/n/%s/b/?compartmentId=%s", namespace, compartmentID)

	var buckets []bucketSummary
	if err := s.doSignedRequest(ctx, cfg, "GET", host, path, &buckets); err != nil {
		return nil, fmt.Errorf("list buckets: %w", err)
	}

	var findings []finding.Finding
	for _, bucket := range buckets {
		// Get detailed bucket info.
		detailPath := fmt.Sprintf("/n/%s/b/%s/", namespace, bucket.Name)
		var detail bucketDetail
		if err := s.doSignedRequest(ctx, cfg, "GET", host, detailPath, &detail); err != nil {
			// Skip individual bucket failures.
			continue
		}

		findings = append(findings, checkBucket(detail, namespace, cfg.Region, asset)...)
	}

	return findings, nil
}

// checkBucket evaluates a single bucket for security issues.
func checkBucket(bucket bucketDetail, namespace, region, asset string) []finding.Finding {
	var findings []finding.Finding

	// Check public access.
	if bucket.PublicAccessType != "" && bucket.PublicAccessType != "NoPublicAccess" {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudOCIBucketPublic,
			Title:   fmt.Sprintf("OCI Object Storage bucket is publicly accessible: %s", bucket.Name),
			Description: fmt.Sprintf(
				"Object Storage bucket %s in namespace %s has public access type %q. "+
					"Any internet user can %s this bucket. Set publicAccessType to "+
					"NoPublicAccess unless public access is explicitly required.",
				bucket.Name, namespace, bucket.PublicAccessType,
				publicAccessAction(bucket.PublicAccessType),
			),
			Severity:     finding.SeverityCritical,
			Asset:        asset,
			Scanner:      scannerTag,
			ProofCommand: fmt.Sprintf("oci os bucket get --name %s --namespace %s --query 'data.\"public-access-type\"'", bucket.Name, namespace),
			Evidence: map[string]any{
				"bucket":             bucket.Name,
				"namespace":          namespace,
				"region":             region,
				"compartment_id":     bucket.CompartmentID,
				"public_access_type": bucket.PublicAccessType,
			},
			DiscoveredAt: time.Now(),
		})
	}

	// Check customer-managed encryption.
	if bucket.KmsKeyID == "" {
		findings = append(findings, finding.Finding{
			CheckID: finding.CheckCloudOCIBucketNoEncryption,
			Title:   fmt.Sprintf("OCI Object Storage bucket has no customer-managed encryption: %s", bucket.Name),
			Description: fmt.Sprintf(
				"Object Storage bucket %s in namespace %s uses only Oracle-managed encryption. "+
					"While Oracle encrypts all data at rest by default, using a customer-managed key "+
					"(CMEK) from OCI Vault provides an additional layer of control. You can revoke "+
					"the key to render data inaccessible and satisfy compliance requirements for "+
					"key ownership.",
				bucket.Name, namespace,
			),
			Severity:     finding.SeverityMedium,
			Asset:        asset,
			Scanner:      scannerTag,
			ProofCommand: fmt.Sprintf("oci os bucket get --name %s --namespace %s --query 'data.\"kms-key-id\"'", bucket.Name, namespace),
			Evidence: map[string]any{
				"bucket":         bucket.Name,
				"namespace":      namespace,
				"region":         region,
				"compartment_id": bucket.CompartmentID,
				"kms_key_id":     "",
			},
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}

// publicAccessAction returns a human-readable action description for the access type.
func publicAccessAction(accessType string) string {
	switch accessType {
	case "ObjectRead":
		return "list and read objects from"
	case "ObjectReadWithoutList":
		return "read objects from (without listing)"
	default:
		return "access"
	}
}
