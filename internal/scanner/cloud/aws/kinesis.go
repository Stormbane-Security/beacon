package aws

import (
	"context"
	"fmt"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/aws"
	kinesis "github.com/aws/aws-sdk-go-v2/service/kinesis"
	kinesistypes "github.com/aws/aws-sdk-go-v2/service/kinesis/types"

	"github.com/stormbane/beacon/internal/finding"
)

func scanKinesis(ctx context.Context, cfg awscfg.Config, accountID, region, asset string) ([]finding.Finding, error) {
	svc := kinesis.NewFromConfig(cfg)
	var findings []finding.Finding

	// List streams (paginated via NextToken).
	var nextToken *string
	firstPage := true
	for {
		input := &kinesis.ListStreamsInput{}
		if nextToken != nil {
			input.NextToken = nextToken
		}
		resp, err := svc.ListStreams(ctx, input)
		if err != nil {
			if firstPage {
				return nil, fmt.Errorf("list streams: %w", err)
			}
			break
		}
		firstPage = false

		for _, streamSummary := range resp.StreamSummaries {
			streamName := awscfg.ToString(streamSummary.StreamName)
			streamARN := awscfg.ToString(streamSummary.StreamARN)

			// Describe stream to get encryption details.
			desc, descErr := svc.DescribeStream(ctx, &kinesis.DescribeStreamInput{
				StreamName: streamSummary.StreamName,
			})
			if descErr != nil || desc.StreamDescription == nil {
				continue
			}

			sd := desc.StreamDescription
			if sd.EncryptionType == kinesistypes.EncryptionTypeNone {
				findings = append(findings, finding.Finding{
					CheckID: finding.CheckCloudAWSKinesisNoEncryption,
					Title:   fmt.Sprintf("Kinesis data stream without server-side encryption: %s", streamName),
					Description: fmt.Sprintf(
						"Kinesis data stream %s in %s does not have server-side encryption enabled. "+
							"Without encryption, data records are stored unencrypted at rest. Enable "+
							"server-side encryption using AWS-managed (aws/kinesis) or customer-managed "+
							"KMS keys to protect data at rest.",
						streamName, region,
					),
					Severity:     finding.SeverityHigh,
					Asset:        asset,
					Scanner:      "cloud/aws",
					ProofCommand: fmt.Sprintf("aws kinesis describe-stream --stream-name %s --region %s --query 'StreamDescription.{EncryptionType:EncryptionType,KeyId:KeyId}'", streamName, region),
					Evidence: map[string]any{
						"account_id":      accountID,
						"region":          region,
						"resource_type":   "kinesis_stream",
						"stream_name":     streamName,
						"stream_arn":      streamARN,
						"encryption_type": string(sd.EncryptionType),
					},
					DiscoveredAt: time.Now(),
				})
			}
		}

		if resp.HasMoreStreams == nil || !*resp.HasMoreStreams {
			break
		}
		nextToken = resp.NextToken
	}

	return findings, nil
}
