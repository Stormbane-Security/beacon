package gcp

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/api/option"
	pubsub "google.golang.org/api/pubsub/v1"

	"github.com/stormbane-security/beacon/internal/finding"
)

func scanPubSub(ctx context.Context, projectID, asset string, opts []option.ClientOption) ([]finding.Finding, error) {
	svc, err := pubsub.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("pubsub service: %w", err)
	}

	var findings []finding.Finding
	project := fmt.Sprintf("projects/%s", projectID)

	var pageToken string
	for {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		call := svc.Projects.Topics.List(project).Context(ctx)
		if pageToken != "" {
			call = call.PageToken(pageToken)
		}
		resp, err := call.Do()
		if err != nil {
			break // Non-fatal: Pub/Sub API may not be enabled.
		}

		for _, topic := range resp.Topics {
			findings = append(findings, checkTopicEncryption(topic, projectID, asset)...)
		}

		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}

	return findings, nil
}

// checkTopicEncryption checks if a Pub/Sub topic uses customer-managed encryption.
func checkTopicEncryption(topic *pubsub.Topic, projectID, asset string) []finding.Finding {
	if topic.KmsKeyName != "" {
		return nil
	}

	shortName := lastPathSegment(topic.Name)

	return []finding.Finding{{
		CheckID: finding.CheckCloudGCPPubSubNoEncryption,
		Title:   fmt.Sprintf("Pub/Sub topic without customer-managed encryption key: %s", shortName),
		Description: fmt.Sprintf(
			"Pub/Sub topic %s in project %s uses Google-managed encryption keys instead of "+
				"customer-managed encryption keys (CMEK). While Google-managed keys provide "+
				"encryption at rest, CMEK gives you control over key rotation, access policies, "+
				"and the ability to revoke access to data by disabling the key.",
			shortName, projectID,
		),
		Severity:     finding.SeverityLow,
		Asset:        asset,
		Scanner:      "cloud/gcp",
		ProofCommand: fmt.Sprintf("gcloud pubsub topics describe %s --project=%s --format='get(kmsKeyName)'", shortName, projectID),
		Evidence: map[string]any{
			"topic":         shortName,
			"full_name":     topic.Name,
			"resource_type": "pubsub_topic",
			"project_id":    projectID,
		},
		DiscoveredAt: time.Now(),
	}}
}
