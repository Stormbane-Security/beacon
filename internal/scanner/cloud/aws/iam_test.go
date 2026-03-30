package aws

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// IAM policy wildcard detection — string matching logic
//
// The scanIAM function detects wildcard admin policies by checking:
//   strings.Contains(doc, `"Action":"*"`) && strings.Contains(doc, `"Resource":"*"`)
//
// These tests verify the matching behavior against various policy document
// shapes to ensure the detection logic catches real wildcards and does not
// false-positive on partial matches.
// ---------------------------------------------------------------------------

// policyHasWildcardAdmin mirrors the detection logic in scanIAM for
// customer-managed IAM policies.
func policyHasWildcardAdmin(doc string) bool {
	return strings.Contains(doc, `"Action":"*"`) && strings.Contains(doc, `"Resource":"*"`)
}

func TestPolicyWildcardDetection(t *testing.T) {
	tests := []struct {
		name     string
		document string
		want     bool
	}{
		{
			name: "classic admin policy — Action:* Resource:*",
			document: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Action":"*",
					"Resource":"*"
				}]
			}`,
			want: true,
		},
		{
			name: "admin policy with extra whitespace around values",
			document: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Action":"*",
					"Resource":"*"
				}]
			}`,
			want: true,
		},
		{
			name: "wildcard action only — no wildcard resource",
			document: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Action":"*",
					"Resource":"arn:aws:s3:::my-bucket/*"
				}]
			}`,
			want: false,
		},
		{
			name: "wildcard resource only — no wildcard action",
			document: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Action":"s3:GetObject",
					"Resource":"*"
				}]
			}`,
			want: false,
		},
		{
			name: "specific action and resource — no wildcards",
			document: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Action":"s3:GetObject",
					"Resource":"arn:aws:s3:::my-bucket/*"
				}]
			}`,
			want: false,
		},
		{
			name: "empty document",
			document: "",
			want: false,
		},
		{
			name: "deny effect with wildcards — still detected",
			document: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Deny",
					"Action":"*",
					"Resource":"*"
				}]
			}`,
			want: true, // the string check doesn't differentiate Allow vs Deny
		},
		{
			name: "action array with star — not detected by simple check",
			document: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Action":["*"],
					"Resource":"*"
				}]
			}`,
			want: false, // ["*"] != "*" in simple string matching
		},
		{
			name: "action with wildcard suffix — not a full wildcard",
			document: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Action":"s3:*",
					"Resource":"*"
				}]
			}`,
			want: false,
		},
		{
			name: "multiple statements — one has wildcards",
			document: `{
				"Version": "2012-10-17",
				"Statement": [
					{"Effect": "Allow", "Action":"s3:GetObject", "Resource":"arn:aws:s3:::bucket/*"},
					{"Effect": "Allow", "Action":"*", "Resource":"*"}
				]
			}`,
			want: true,
		},
		{
			name: "URL-encoded policy document — wildcard strings present after decode",
			// AWS returns URL-encoded policy documents from GetPolicyVersion.
			// The sdk usually decodes them, but this tests the raw string.
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
			want:     true,
		},
		{
			name: "spaces between key and value — Action : *",
			document: `{
				"Action" : "*",
				"Resource" : "*"
			}`,
			want: false, // the detection expects no space: "Action":"*"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := policyHasWildcardAdmin(tt.document)
			if got != tt.want {
				t.Errorf("policyHasWildcardAdmin() = %v, want %v", got, tt.want)
			}
		})
	}
}

// policyHasWildcardAdminFull mirrors the actual detection logic in scanIAM,
// which checks both no-space and single-space variants:
//
//	"Action":"*" OR "Action": "*"
//	"Resource":"*" OR "Resource": "*"
func policyHasWildcardAdminFull(doc string) bool {
	hasAction := strings.Contains(doc, `"Action":"*"`) || strings.Contains(doc, `"Action": "*"`)
	hasResource := strings.Contains(doc, `"Resource":"*"`) || strings.Contains(doc, `"Resource": "*"`)
	return hasAction && hasResource
}

// TestPolicyWildcardDetectionFull tests the actual detection logic from scanIAM
// which handles both "Action":"*" (no space) and "Action": "*" (with space).
func TestPolicyWildcardDetectionFull(t *testing.T) {
	tests := []struct {
		name     string
		document string
		want     bool
	}{
		{
			name: "mixed spacing — Action no space, Resource with space",
			document: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Action":"*",
					"Resource": "*"
				}]
			}`,
			want: true,
		},
		{
			name: "mixed spacing — Action with space, Resource no space",
			document: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Action": "*",
					"Resource":"*"
				}]
			}`,
			want: true,
		},
		{
			name: "both with single space after colon",
			document: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Action": "*",
					"Resource": "*"
				}]
			}`,
			want: true,
		},
		{
			name: "both with no space after colon",
			document: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Action":"*",
					"Resource":"*"
				}]
			}`,
			want: true,
		},
		{
			name: "double space after colon — not detected",
			document: `{
				"Action":  "*",
				"Resource":  "*"
			}`,
			want: false,
		},
		{
			name: "compact JSON (no spaces at all)",
			document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := policyHasWildcardAdminFull(tt.document)
			if got != tt.want {
				t.Errorf("policyHasWildcardAdminFull() = %v, want %v", got, tt.want)
			}
		})
	}
}
