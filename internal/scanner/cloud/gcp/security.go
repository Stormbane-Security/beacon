package gcp

import (
	"context"
	"fmt"
	"time"

	bigqueryapi "google.golang.org/api/bigquery/v2"
	"google.golang.org/api/cloudfunctions/v1"
	"google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/cloudresourcemanager/v1"
	computeapi "google.golang.org/api/compute/v1"
	"google.golang.org/api/option"

	"github.com/stormbane-security/beacon/internal/finding"
)

// scanSecurity runs project-level and account-level security checks that don't
// fit neatly into a single resource category (VPC flow logs, KMS, Cloud Functions,
// BigQuery, org policy).
func scanSecurity(ctx context.Context, projectID, asset string, opts []option.ClientOption) ([]finding.Finding, error) {
	var findings []finding.Finding

	// VPC Flow Logs
	flowLogFindings, err := checkVPCFlowLogs(ctx, projectID, asset, opts)
	if err == nil {
		findings = append(findings, flowLogFindings...)
	}

	// KMS key rotation
	kmsFindings, err := checkKMSRotation(ctx, projectID, asset, opts)
	if err == nil {
		findings = append(findings, kmsFindings...)
	}

	// Cloud Functions unauthenticated access
	cfFindings, err := checkCloudFunctionAuth(ctx, projectID, asset, opts)
	if err == nil {
		findings = append(findings, cfFindings...)
	}

	// BigQuery public datasets
	bqFindings, err := checkBigQueryPublic(ctx, projectID, asset, opts)
	if err == nil {
		findings = append(findings, bqFindings...)
	}

	// Org policy restriction
	orgFindings, err := checkOrgPolicyRestriction(ctx, projectID, asset, opts)
	if err == nil {
		findings = append(findings, orgFindings...)
	}

	return findings, nil
}

// checkVPCFlowLogs lists all subnetworks in the project and flags any that do
// not have VPC Flow Logs enabled.
func checkVPCFlowLogs(ctx context.Context, projectID, asset string, opts []option.ClientOption) ([]finding.Finding, error) {
	svc, err := computeapi.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("compute service: %w", err)
	}

	var findings []finding.Finding

	if err := svc.Subnetworks.AggregatedList(projectID).Context(ctx).Pages(ctx,
		func(page *computeapi.SubnetworkAggregatedList) error {
			for _, items := range page.Items {
				for _, subnet := range items.Subnetworks {
					findings = append(findings, checkSubnetFlowLogs(subnet, projectID, asset)...)
				}
			}
			return nil
		}); err != nil {
		return nil, fmt.Errorf("list subnetworks: %w", err)
	}

	return findings, nil
}

// checkSubnetFlowLogs checks a single subnet for VPC Flow Logs configuration.
func checkSubnetFlowLogs(subnet *computeapi.Subnetwork, projectID, asset string) []finding.Finding {
	flowLogsEnabled := subnet.LogConfig != nil && subnet.LogConfig.Enable
	if flowLogsEnabled {
		return nil
	}

	return []finding.Finding{{
		CheckID: finding.CheckCloudGCPNoVPCFlowLogs,
		Title:   fmt.Sprintf("VPC Flow Logs not enabled on subnet: %s", subnet.Name),
		Description: fmt.Sprintf(
			"VPC Flow Logs are not enabled on subnet %s in project %s. "+
				"Flow logs capture IP traffic metadata for network monitoring and forensics.",
			subnet.Name, projectID,
		),
		Severity:     finding.SeverityMedium,
		Asset:        asset,
		Scanner:      "cloud/gcp",
		ProofCommand: fmt.Sprintf("gcloud compute networks subnets describe %s --region=%s --project=%s --format='get(logConfig)'", subnet.Name, regionFromSelfLink(subnet.Region), projectID),
		Evidence: map[string]any{
			"subnet":        subnet.Name,
			"resource_type": "vpc_subnetwork",
			"project_id":    projectID,
			"region":        regionFromSelfLink(subnet.Region),
			"network":       lastPathSegment(subnet.Network),
		},
		DiscoveredAt: time.Now(),
	}}
}

// checkKMSRotation lists all KMS key rings and crypto keys, flagging ENCRYPT_DECRYPT
// keys without a rotation period configured.
func checkKMSRotation(ctx context.Context, projectID, asset string, opts []option.ClientOption) ([]finding.Finding, error) {
	svc, err := cloudkms.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("kms service: %w", err)
	}

	var findings []finding.Finding

	// List key rings across all locations.
	parent := fmt.Sprintf("projects/%s/locations/-", projectID)
	var pageToken string
	for {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		call := svc.Projects.Locations.KeyRings.List(parent).Context(ctx)
		if pageToken != "" {
			call = call.PageToken(pageToken)
		}
		resp, err := call.Do()
		if err != nil {
			break // Non-fatal: KMS API may not be enabled.
		}

		for _, keyRing := range resp.KeyRings {
			keyFindings, err := checkKeyRingRotation(ctx, svc, keyRing.Name, projectID, asset)
			if err == nil {
				findings = append(findings, keyFindings...)
			}
		}

		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}

	return findings, nil
}

// checkKeyRingRotation checks all crypto keys in a key ring for rotation configuration.
func checkKeyRingRotation(ctx context.Context, svc *cloudkms.Service, keyRingName, projectID, asset string) ([]finding.Finding, error) {
	var findings []finding.Finding
	var pageToken string

	for {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		call := svc.Projects.Locations.KeyRings.CryptoKeys.List(keyRingName).Context(ctx)
		if pageToken != "" {
			call = call.PageToken(pageToken)
		}
		resp, err := call.Do()
		if err != nil {
			return findings, err
		}

		for _, key := range resp.CryptoKeys {
			findings = append(findings, checkCryptoKeyRotation(key, projectID, asset)...)
		}

		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}

	return findings, nil
}

// checkCryptoKeyRotation checks a single KMS crypto key for rotation period.
func checkCryptoKeyRotation(key *cloudkms.CryptoKey, projectID, asset string) []finding.Finding {
	// Only check ENCRYPT_DECRYPT keys — asymmetric keys don't support automatic rotation.
	if key.Purpose != "ENCRYPT_DECRYPT" {
		return nil
	}

	if key.RotationPeriod != "" {
		return nil
	}

	shortName := lastPathSegment(key.Name)

	return []finding.Finding{{
		CheckID: finding.CheckCloudGCPKMSNoRotation,
		Title:   fmt.Sprintf("Cloud KMS key has no automatic rotation: %s", shortName),
		Description: "Cloud KMS key does not have automatic rotation period configured.",
		Severity:     finding.SeverityMedium,
		Asset:        asset,
		Scanner:      "cloud/gcp",
		ProofCommand: fmt.Sprintf("gcloud kms keys describe %s --format='get(rotationPeriod)'", key.Name),
		Evidence: map[string]any{
			"key_name":      shortName,
			"full_name":     key.Name,
			"resource_type": "kms_crypto_key",
			"project_id":    projectID,
			"purpose":       key.Purpose,
		},
		DiscoveredAt: time.Now(),
	}}
}

// checkCloudFunctionAuth lists Cloud Functions (v1) and checks IAM policy for
// unauthenticated invocation.
func checkCloudFunctionAuth(ctx context.Context, projectID, asset string, opts []option.ClientOption) ([]finding.Finding, error) {
	svc, err := cloudfunctions.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("cloudfunctions service: %w", err)
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

		call := svc.Projects.Locations.Functions.List(parent).Context(ctx)
		if pageToken != "" {
			call = call.PageToken(pageToken)
		}
		resp, err := call.Do()
		if err != nil {
			break // Non-fatal: API may not be enabled.
		}

		for _, fn := range resp.Functions {
			findings = append(findings, checkFunctionAuth(ctx, svc, fn, projectID, asset)...)
		}

		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}

	return findings, nil
}

// checkFunctionAuth checks a single Cloud Function's IAM policy for public access.
func checkFunctionAuth(ctx context.Context, svc *cloudfunctions.Service, fn *cloudfunctions.CloudFunction, projectID, asset string) []finding.Finding {
	policy, err := svc.Projects.Locations.Functions.GetIamPolicy(fn.Name).Context(ctx).Do()
	if err != nil {
		return nil
	}

	for _, binding := range policy.Bindings {
		if binding.Role != "roles/cloudfunctions.invoker" {
			continue
		}
		for _, member := range binding.Members {
			if member == "allUsers" || member == "allAuthenticatedUsers" {
				shortName := lastPathSegment(fn.Name)
				region := extractLocationFromFunctionName(fn.Name)
				return []finding.Finding{{
					CheckID: finding.CheckCloudGCPCloudFunctionNoAuth,
					Title:   fmt.Sprintf("Cloud Function allows unauthenticated invocation: %s", shortName),
					Description: "Cloud Function allows unauthenticated invocation. Anyone can call this function.",
					Severity:     finding.SeverityHigh,
					Asset:        asset,
					Scanner:      "cloud/gcp",
					ProofCommand: fmt.Sprintf("gcloud functions get-iam-policy %s --region=%s --project=%s", shortName, region, projectID),
					Evidence: map[string]any{
						"function":      shortName,
						"resource_type": "cloud_function",
						"project_id":    projectID,
						"region":        region,
						"role":          binding.Role,
						"member":        member,
					},
					DiscoveredAt: time.Now(),
				}}
			}
		}
	}

	return nil
}

// checkBigQueryPublic lists BigQuery datasets and checks access entries for public access.
func checkBigQueryPublic(ctx context.Context, projectID, asset string, opts []option.ClientOption) ([]finding.Finding, error) {
	// BigQuery uses the bigquery API, but google.golang.org/api/bigquery/v2 is available
	// via the same google.golang.org/api dependency.
	// We import inline to avoid adding a top-level dependency that might bloat builds
	// if the API is not available. Instead, we use the REST-based approach via the
	// google.golang.org/api/bigquery/v2 package.

	// NOTE: The bigquery/v2 package is part of google.golang.org/api.
	// We'll use a deferred import pattern — but since Go doesn't support that,
	// we do a lazy service creation here.
	return checkBigQueryPublicInternal(ctx, projectID, asset, opts)
}

// checkBigQueryPublicInternal performs the actual BigQuery public access check.
func checkBigQueryPublicInternal(ctx context.Context, projectID, asset string, opts []option.ClientOption) ([]finding.Finding, error) {
	// Use the REST discovery-based client from google.golang.org/api.
	// BigQuery dataset access is checked via the datasets.list + datasets.get API.
	//
	// Since google.golang.org/api/bigquery/v2 may not be generated in all versions,
	// we use the cloudresourcemanager approach of calling via the service helper.
	// For simplicity and to avoid adding a new import that may not exist,
	// we skip this check if the API is unavailable. The check ID is already
	// registered and will be populated when the API becomes available.
	//
	// This is a placeholder that returns nil — the BigQuery v2 client usage
	// follows the same pattern as other GCP scanners.

	// Attempt BigQuery API via google.golang.org/api/bigquery/v2.
	return checkBigQueryDatasets(ctx, projectID, asset, opts)
}

// checkBigQueryDatasets lists BigQuery datasets and checks their access entries
// for public (allUsers / allAuthenticatedUsers) access.
func checkBigQueryDatasets(ctx context.Context, projectID, asset string, opts []option.ClientOption) ([]finding.Finding, error) {
	svc, err := bigqueryapi.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("bigquery service: %w", err)
	}

	var findings []finding.Finding

	resp, err := svc.Datasets.List(projectID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("list datasets: %w", err)
	}

	for _, ds := range resp.Datasets {
		if ds.DatasetReference == nil {
			continue
		}
		datasetID := ds.DatasetReference.DatasetId

		dataset, err := svc.Datasets.Get(projectID, datasetID).Context(ctx).Do()
		if err != nil {
			continue
		}

		for _, access := range dataset.Access {
			if access.IamMember == "allUsers" || access.IamMember == "allAuthenticatedUsers" {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudGCPBigQueryPublic,
					Title:   fmt.Sprintf("BigQuery dataset is publicly accessible: %s", datasetID),
					Description: fmt.Sprintf(
						"BigQuery dataset %s in project %s grants access to %s. "+
							"Any internet user can query this dataset. Remove the public "+
							"access entry and restrict to specific principals.",
						datasetID, projectID, access.IamMember,
					),
					Severity:     finding.SeverityHigh,
					Asset:        asset,
					Scanner:      "cloud/gcp",
					ProofCommand: fmt.Sprintf("bq show --format=prettyjson %s:%s | jq '.access'", projectID, datasetID),
					Evidence: map[string]any{
						"dataset_id":    datasetID,
						"resource_type": "bigquery_dataset",
						"project_id":    projectID,
						"member":        access.IamMember,
						"role":          access.Role,
					},
					DiscoveredAt: time.Now(),
				})
				break // One finding per dataset is sufficient.
			}
		}
	}

	return findings, nil
}

// checkOrgPolicyRestriction checks if the domain-restricted sharing org policy
// (constraints/iam.allowedPolicyMemberDomains) is configured.
func checkOrgPolicyRestriction(ctx context.Context, projectID, asset string, opts []option.ClientOption) ([]finding.Finding, error) {
	svc, err := cloudresourcemanager.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("cloudresourcemanager: %w", err)
	}

	// Try to get the effective org policy for domain restriction.
	resp, err := svc.Projects.GetEffectiveOrgPolicy(
		"projects/"+projectID,
		&cloudresourcemanager.GetEffectiveOrgPolicyRequest{
			Constraint: "constraints/iam.allowedPolicyMemberDomains",
		},
	).Context(ctx).Do()
	if err != nil {
		// If the API returns an error (e.g., not an org, constraint not found),
		// emit the finding since the policy is effectively not configured.
		return []finding.Finding{{
			CheckID: finding.CheckCloudGCPNoOrgPolicyRestrict,
			Title:   fmt.Sprintf("GCP project has no org policy for domain-restricted sharing: %s", projectID),
			Description: "Organization policy for domain-restricted sharing is not configured. " +
				"Resources can be shared with any Google account.",
			Severity:     finding.SeverityMedium,
			Asset:        asset,
			Scanner:      "cloud/gcp",
			ProofCommand: fmt.Sprintf("gcloud resource-manager org-policies describe constraints/iam.allowedPolicyMemberDomains --project=%s --effective", projectID),
			Evidence: map[string]any{
				"resource_type": "gcp_project",
				"project_id":    projectID,
				"constraint":    "constraints/iam.allowedPolicyMemberDomains",
			},
			DiscoveredAt: time.Now(),
		}}, nil
	}

	// If the response has no list policy or the list policy has no allowed values,
	// the constraint is not effectively restricting anything.
	if resp.ListPolicy == nil || (len(resp.ListPolicy.AllowedValues) == 0 && resp.ListPolicy.AllValues == "") {
		return []finding.Finding{{
			CheckID: finding.CheckCloudGCPNoOrgPolicyRestrict,
			Title:   fmt.Sprintf("GCP project has no org policy for domain-restricted sharing: %s", projectID),
			Description: "Organization policy for domain-restricted sharing is not configured. " +
				"Resources can be shared with any Google account.",
			Severity:     finding.SeverityMedium,
			Asset:        asset,
			Scanner:      "cloud/gcp",
			ProofCommand: fmt.Sprintf("gcloud resource-manager org-policies describe constraints/iam.allowedPolicyMemberDomains --project=%s --effective", projectID),
			Evidence: map[string]any{
				"resource_type": "gcp_project",
				"project_id":    projectID,
				"constraint":    "constraints/iam.allowedPolicyMemberDomains",
			},
			DiscoveredAt: time.Now(),
		}}, nil
	}

	return nil, nil
}

// regionFromSelfLink extracts the region from a GCP self-link URL.
func regionFromSelfLink(link string) string {
	return lastPathSegment(link)
}

// lastPathSegment returns the last segment of a slash-separated path.
func lastPathSegment(name string) string {
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '/' {
			return name[i+1:]
		}
	}
	return name
}

// extractLocationFromFunctionName extracts the location from a Cloud Function resource name.
// Format: projects/{project}/locations/{location}/functions/{function}
func extractLocationFromFunctionName(name string) string {
	return extractRegion(name) // Reuses the existing helper from cloudrun.go
}
