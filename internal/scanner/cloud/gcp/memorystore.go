package gcp

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/api/option"
	redis "google.golang.org/api/redis/v1"

	"github.com/stormbane-security/beacon/internal/finding"
)

func scanMemorystore(ctx context.Context, projectID, asset string, opts []option.ClientOption) ([]finding.Finding, error) {
	svc, err := redis.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("redis service: %w", err)
	}

	var findings []finding.Finding
	parent := fmt.Sprintf("projects/%s/locations/-", projectID)

	var pageToken string
	for {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		call := svc.Projects.Locations.Instances.List(parent).Context(ctx)
		if pageToken != "" {
			call = call.PageToken(pageToken)
		}
		resp, err := call.Do()
		if err != nil {
			break // Non-fatal: Redis API may not be enabled.
		}

		for _, instance := range resp.Instances {
			findings = append(findings, checkMemorystoreAuth(instance, projectID, asset)...)
			findings = append(findings, checkMemorystoreTransitEncryption(instance, projectID, asset)...)
		}

		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}

	return findings, nil
}

// checkMemorystoreAuth checks if a Memorystore Redis instance has AUTH enabled.
func checkMemorystoreAuth(instance *redis.Instance, projectID, asset string) []finding.Finding {
	if instance.AuthEnabled {
		return nil
	}

	shortName := lastPathSegment(instance.Name)
	region := extractRegion(instance.Name)

	return []finding.Finding{{
		CheckID: finding.CheckCloudGCPMemorystoreNoAuth,
		Title:   fmt.Sprintf("Memorystore Redis instance without AUTH enabled: %s", shortName),
		Description: fmt.Sprintf(
			"Memorystore Redis instance %s in project %s does not have AUTH enabled. "+
				"Without AUTH, any client that can reach the instance on the VPC network can "+
				"read and write data without credentials. Enable AUTH to require clients to "+
				"authenticate before executing commands.",
			shortName, projectID,
		),
		Severity:     finding.SeverityHigh,
		Asset:        asset,
		Scanner:      "cloud/gcp",
		ProofCommand: fmt.Sprintf("gcloud redis instances describe %s --region=%s --project=%s --format='get(authEnabled)'", shortName, region, projectID),
		Evidence: map[string]any{
			"instance":      shortName,
			"full_name":     instance.Name,
			"resource_type": "memorystore_redis",
			"project_id":    projectID,
			"region":        region,
			"tier":          instance.Tier,
		},
		DiscoveredAt: time.Now(),
	}}
}

// checkMemorystoreTransitEncryption checks if a Memorystore Redis instance has
// in-transit encryption enabled.
func checkMemorystoreTransitEncryption(instance *redis.Instance, projectID, asset string) []finding.Finding {
	if instance.TransitEncryptionMode == "SERVER_AUTHENTICATION" {
		return nil
	}

	shortName := lastPathSegment(instance.Name)
	region := extractRegion(instance.Name)

	return []finding.Finding{{
		CheckID: finding.CheckCloudGCPMemorystoreNoTransitEncryption,
		Title:   fmt.Sprintf("Memorystore Redis instance without in-transit encryption: %s", shortName),
		Description: fmt.Sprintf(
			"Memorystore Redis instance %s in project %s does not have in-transit encryption "+
				"enabled (TransitEncryptionMode is %q, expected \"SERVER_AUTHENTICATION\"). "+
				"Without in-transit encryption, data between the application and Redis is sent "+
				"in plaintext over the VPC network, allowing network-level eavesdropping. "+
				"Enable in-transit encryption to protect data in flight.",
			shortName, projectID, instance.TransitEncryptionMode,
		),
		Severity:     finding.SeverityHigh,
		Asset:        asset,
		Scanner:      "cloud/gcp",
		ProofCommand: fmt.Sprintf("gcloud redis instances describe %s --region=%s --project=%s --format='get(transitEncryptionMode)'", shortName, region, projectID),
		Evidence: map[string]any{
			"instance":                shortName,
			"full_name":               instance.Name,
			"resource_type":           "memorystore_redis",
			"project_id":              projectID,
			"region":                  region,
			"tier":                    instance.Tier,
			"transit_encryption_mode": instance.TransitEncryptionMode,
		},
		DiscoveredAt: time.Now(),
	}}
}
