// Package terraform performs static analysis of Terraform/OpenTofu HCL files,
// detecting common infrastructure misconfigurations without executing any network
// requests. All checks are pure file analysis — no Terraform state or plan required.
//
// Supported providers: AWS, GCP, Azure (partial).
// Supported resource types: aws_s3_bucket, aws_security_group, aws_instance,
//   aws_db_instance, aws_iam_*, aws_ecr_repository, aws_cloudfront_distribution,
//   aws_lb_listener, google_storage_bucket, google_container_cluster.
package terraform

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/finding"
)

// ScanFiles analyses all .tf files in the provided paths (files or directories)
// and returns findings for detected misconfigurations.
func ScanFiles(paths []string) ([]finding.Finding, error) {
	var files []string
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("terraform: %w", err)
		}
		if fi.IsDir() {
			entries, err := collectTFFiles(p)
			if err != nil {
				return nil, err
			}
			files = append(files, entries...)
		} else {
			files = append(files, p)
		}
	}

	var findings []finding.Finding
	for _, f := range files {
		ff, err := analyseFile(f)
		if err != nil {
			// Skip files that can't be read/parsed — report an info finding.
			findings = append(findings, finding.Finding{
				CheckID:      finding.CheckTerraformSecretsInCode,
				Scanner:      "terraform",
				Severity:     finding.SeverityInfo,
				Title:        fmt.Sprintf("Could not parse Terraform file: %s", filepath.Base(f)),
				Description:  err.Error(),
				Asset:        f,
				DiscoveredAt: time.Now(),
			})
			continue
		}
		findings = append(findings, ff...)
	}
	return findings, nil
}

func collectTFFiles(dir string) ([]string, error) {
	var files []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("terraform: reading dir %s: %w", dir, err)
	}
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		if e.IsDir() {
			// Recurse into subdirectories (modules).
			sub, err := collectTFFiles(path)
			if err != nil {
				return nil, err
			}
			files = append(files, sub...)
		} else if strings.HasSuffix(e.Name(), ".tf") || strings.HasSuffix(e.Name(), ".tf.json") {
			files = append(files, path)
		}
	}
	return files, nil
}

// hclFile represents a parsed Terraform file — a flat list of resource blocks
// with their attributes extracted by a simple regex-based parser.
type hclFile struct {
	path      string
	resources []hclResource
	// globals holds top-level terraform{} and backend{} block attributes.
	globals map[string]string
}

type hclResource struct {
	resourceType string // e.g. "aws_s3_bucket"
	name         string // e.g. "my_bucket"
	attrs        map[string]string
	// subBlocks holds named sub-block content, e.g. "ingress" -> raw lines
	subBlocks map[string][]string
	// lineNo is the first line of the resource block in the file.
	lineNo int
}

// analyseFile parses a .tf file and runs all checks against its resources.
func analyseFile(path string) ([]finding.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	hf := &hclFile{path: path, globals: map[string]string{}}
	if err := parseHCLFromScanner(bufio.NewScanner(f), hf); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	var findings []finding.Finding
	for _, res := range hf.resources {
		ff := runChecks(hf.path, res)
		findings = append(findings, ff...)
	}
	// Check backend configuration for public state.
	findings = append(findings, checkTFState(hf)...)
	return findings, nil
}

// ---- HCL parser --------------------------------------------------------

func parseHCLFromScanner(scanner *bufio.Scanner, hf *hclFile) error {
	type stackEntry struct {
		kind  string // "resource", "sub", "other"
		res   *hclResource
		block string // sub-block name
	}
	var stack []stackEntry
	lineNo := 0
	inBlockComment := false

	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())

		// Track multi-line /* ... */ comments.
		if inBlockComment {
			if strings.Contains(line, "*/") {
				inBlockComment = false
			}
			continue
		}

		// Skip comments and blank lines.
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "/*") {
			if !strings.Contains(line, "*/") {
				inBlockComment = true
			}
			continue
		}

		// Opening brace — could be a block header.
		if strings.HasSuffix(line, "{") {
			header := strings.TrimSuffix(line, "{")
			header = strings.TrimSpace(header)
			tokens := tokenise(header)

			if len(tokens) >= 3 && tokens[0] == "resource" {
				res := &hclResource{
					resourceType: unquote(tokens[1]),
					name:         unquote(tokens[2]),
					attrs:        map[string]string{},
					subBlocks:    map[string][]string{},
					lineNo:       lineNo,
				}
				hf.resources = append(hf.resources, *res)
				stack = append(stack, stackEntry{kind: "resource", res: &hf.resources[len(hf.resources)-1]})
				continue
			}

			// Sub-block inside a resource (e.g. ingress {}, metadata_options {}).
			if len(stack) > 0 && stack[len(stack)-1].kind == "resource" && len(tokens) == 1 {
				blockName := tokens[0]
				stack = append(stack, stackEntry{kind: "sub", res: stack[len(stack)-1].res, block: blockName})
				continue
			}

			// Top-level terraform{} or backend{}.
			if len(tokens) == 1 && tokens[0] == "terraform" {
				stack = append(stack, stackEntry{kind: "other"})
				continue
			}
			if len(tokens) == 2 && tokens[0] == "backend" {
				stack = append(stack, stackEntry{kind: "backend"})
				continue
			}

			// Anything else — push a generic frame to track depth.
			stack = append(stack, stackEntry{kind: "other"})
			continue
		}

		// Closing brace.
		if line == "}" || line == "}," {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			continue
		}

		// Attribute assignment inside a resource block.
		if len(stack) > 0 {
			top := &stack[len(stack)-1]
			if top.kind == "resource" || top.kind == "backend" {
				if k, v, ok := parseAttr(line); ok {
					if top.kind == "resource" && top.res != nil {
						top.res.attrs[k] = v
					} else if top.kind == "backend" {
						hf.globals["backend."+k] = v
					}
				}
			} else if top.kind == "sub" && top.res != nil {
				top.res.subBlocks[top.block] = append(top.res.subBlocks[top.block], line)
			}
		}
	}
	return scanner.Err()
}

var reAttr = regexp.MustCompile(`^([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+)$`)

func parseAttr(line string) (key, value string, ok bool) {
	// Strip inline comments.
	if i := strings.Index(line, " #"); i > 0 {
		line = strings.TrimSpace(line[:i])
	}
	m := reAttr.FindStringSubmatch(line)
	if m == nil {
		return "", "", false
	}
	return m[1], normaliseValue(m[2]), true
}

func normaliseValue(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ",")
	s = strings.TrimSpace(s)
	// Unquote strings.
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return strings.ToLower(s)
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func tokenise(s string) []string {
	var tokens []string
	inQuote := false
	var cur strings.Builder
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case r == ' ' || r == '\t':
			if inQuote {
				cur.WriteRune(r)
			} else if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

// ---- Checks ------------------------------------------------------------

func runChecks(path string, res hclResource) []finding.Finding {
	var ff []finding.Finding
	switch res.resourceType {
	case "aws_s3_bucket":
		ff = append(ff, checkS3Bucket(path, res)...)
	case "aws_s3_bucket_public_access_block":
		// Negative check — if block_public_acls is false, flag it.
		ff = append(ff, checkS3PublicAccessBlock(path, res)...)
	case "aws_security_group":
		ff = append(ff, checkSecurityGroup(path, res)...)
	case "aws_db_instance":
		ff = append(ff, checkRDSInstance(path, res)...)
	case "aws_instance":
		ff = append(ff, checkEC2Instance(path, res)...)
	case "aws_iam_role_policy", "aws_iam_policy", "aws_iam_user_policy":
		ff = append(ff, checkIAMPolicy(path, res)...)
	case "aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment":
		ff = append(ff, checkIAMAdminAttachment(path, res)...)
	case "aws_ecr_repository":
		ff = append(ff, checkECRRepo(path, res)...)
	case "aws_cloudfront_distribution":
		ff = append(ff, checkCloudFront(path, res)...)
	case "aws_lb_listener", "aws_alb_listener":
		ff = append(ff, checkLBListener(path, res)...)
	case "google_storage_bucket":
		ff = append(ff, checkGCSBucket(path, res)...)
	case "google_container_cluster":
		ff = append(ff, checkGKECluster(path, res)...)
	}
	// Check all resources for hardcoded secrets.
	ff = append(ff, checkSecretsInAttrs(path, res)...)
	return ff
}

// ---- AWS checks --------------------------------------------------------

func checkS3Bucket(path string, res hclResource) []finding.Finding {
	var ff []finding.Finding
	// Old-style ACL attribute (pre-provider v4).
	if acl, ok := res.attrs["acl"]; ok {
		if acl == "public-read" || acl == "public-read-write" || acl == "authenticated-read" {
			ff = append(ff, makeFinding(
				finding.CheckTerraformS3BucketPublic,
				finding.SeverityHigh,
				fmt.Sprintf("S3 bucket %q has public ACL: acl = %q", res.name, acl),
				fmt.Sprintf("The S3 bucket %q in %s has acl = \"%s\", which exposes bucket contents to the internet. Set acl = \"private\" or remove the acl attribute and use an explicit bucket policy.", res.name, filepath.Base(path), acl),
				path, res.lineNo,
				fmt.Sprintf(`resource "aws_s3_bucket_public_access_block" "%s_block" {
  bucket                  = aws_s3_bucket.%s.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}`, res.name, res.name),
			))
		}
	}
	return ff
}

func checkS3PublicAccessBlock(path string, res hclResource) []finding.Finding {
	var ff []finding.Finding
	falseFields := []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"}
	for _, field := range falseFields {
		if v, ok := res.attrs[field]; ok && v == "false" {
			ff = append(ff, makeFinding(
				finding.CheckTerraformS3BucketPublic,
				finding.SeverityHigh,
				fmt.Sprintf("S3 public access block %q has %s = false", res.name, field),
				fmt.Sprintf("Setting %s = false in the public access block for %q (%s) re-enables public access controls that should be blocked. Change all four fields to true.", field, res.name, filepath.Base(path)),
				path, res.lineNo,
				fmt.Sprintf(`resource "aws_s3_bucket_public_access_block" "%s" {
  bucket                  = aws_s3_bucket.main.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}`, res.name),
			))
			break // one finding per resource is enough
		}
	}
	return ff
}

func checkSecurityGroup(path string, res hclResource) []finding.Finding {
	var ff []finding.Finding
	// Check ingress sub-block lines for 0.0.0.0/0 or ::/0 with sensitive ports.
	ingressLines := res.subBlocks["ingress"]
	if checkOpenCIDR(ingressLines) {
		ff = append(ff, makeFinding(
			finding.CheckTerraformSGOpenIngress,
			finding.SeverityHigh,
			fmt.Sprintf("Security group %q allows ingress from 0.0.0.0/0 or ::/0", res.name),
			fmt.Sprintf("The security group %q in %s has an ingress rule that allows traffic from any IP address (0.0.0.0/0 or ::/0). Restrict cidr_blocks to known IP ranges.", res.name, filepath.Base(path)),
			path, res.lineNo,
			fmt.Sprintf(`resource "aws_security_group" "%s" {
  # Replace 0.0.0.0/0 with your trusted CIDR ranges:
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Internal only
  }
}`, res.name),
		))
	}
	// Also check top-level ingress_cidr_blocks (older style).
	if v, ok := res.attrs["ingress_cidr_blocks"]; ok {
		if strings.Contains(v, "0.0.0.0/0") || strings.Contains(v, "::/0") {
			ff = append(ff, makeFinding(
				finding.CheckTerraformSGOpenIngress,
				finding.SeverityHigh,
				fmt.Sprintf("Security group %q has ingress_cidr_blocks open to the world", res.name),
				fmt.Sprintf("The security group %q in %s permits unrestricted inbound access. Restrict to specific IP ranges.", res.name, filepath.Base(path)),
				path, res.lineNo, "",
			))
		}
	}
	return ff
}

func checkOpenCIDR(lines []string) bool {
	for _, l := range lines {
		if strings.Contains(l, "0.0.0.0/0") || strings.Contains(l, "::/0") {
			return true
		}
	}
	return false
}

func checkRDSInstance(path string, res hclResource) []finding.Finding {
	var ff []finding.Finding
	if v, ok := res.attrs["publicly_accessible"]; ok && v == "true" {
		ff = append(ff, makeFinding(
			finding.CheckTerraformRDSPublic,
			finding.SeverityCritical,
			fmt.Sprintf("RDS instance %q is publicly accessible", res.name),
			fmt.Sprintf("The RDS instance %q in %s has publicly_accessible = true, which exposes the database endpoint to the internet. Set publicly_accessible = false and use a VPC security group.", res.name, filepath.Base(path)),
			path, res.lineNo,
			fmt.Sprintf(`resource "aws_db_instance" "%s" {
  publicly_accessible = false
  # Ensure db_subnet_group_name is in a private subnet group
}`, res.name),
		))
	}
	if v, ok := res.attrs["storage_encrypted"]; ok && v == "false" {
		ff = append(ff, makeFinding(
			finding.CheckTerraformRDSUnencrypted,
			finding.SeverityHigh,
			fmt.Sprintf("RDS instance %q has storage_encrypted = false", res.name),
			fmt.Sprintf("The RDS instance %q in %s has unencrypted storage. Set storage_encrypted = true. Note: requires replacing the instance.", res.name, filepath.Base(path)),
			path, res.lineNo,
			fmt.Sprintf(`resource "aws_db_instance" "%s" {
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn
}`, res.name),
		))
	}
	if _, ok := res.attrs["storage_encrypted"]; !ok {
		// Default for RDS is unencrypted unless explicitly set.
		ff = append(ff, makeFinding(
			finding.CheckTerraformRDSUnencrypted,
			finding.SeverityHigh,
			fmt.Sprintf("RDS instance %q does not set storage_encrypted", res.name),
			fmt.Sprintf("The RDS instance %q in %s does not explicitly enable storage encryption (defaults to false). Add storage_encrypted = true.", res.name, filepath.Base(path)),
			path, res.lineNo,
			fmt.Sprintf(`resource "aws_db_instance" "%s" {
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn
}`, res.name),
		))
	}
	return ff
}

func checkEC2Instance(path string, res hclResource) []finding.Finding {
	var ff []finding.Finding

	// Check EBS volumes encrypted.
	ebsLines := res.subBlocks["root_block_device"]
	ebsLines = append(ebsLines, res.subBlocks["ebs_block_device"]...)
	for _, l := range ebsLines {
		if strings.Contains(l, "encrypted") && strings.Contains(l, "false") {
			ff = append(ff, makeFinding(
				finding.CheckTerraformUnencryptedEBS,
				finding.SeverityHigh,
				fmt.Sprintf("EC2 instance %q has an unencrypted EBS volume", res.name),
				fmt.Sprintf("An EBS block device on instance %q in %s has encrypted = false. Set encrypted = true on all block devices.", res.name, filepath.Base(path)),
				path, res.lineNo,
				fmt.Sprintf(`resource "aws_instance" "%s" {
  root_block_device {
    encrypted   = true
    kms_key_id  = aws_kms_key.ebs.arn
    volume_type = "gp3"
  }
}`, res.name),
			))
			break
		}
	}

	// IMDSv1: if http_tokens != "required" in metadata_options.
	metaLines := res.subBlocks["metadata_options"]
	if len(metaLines) > 0 {
		hasRequired := false
		for _, l := range metaLines {
			if strings.Contains(l, "http_tokens") && strings.Contains(l, "required") {
				hasRequired = true
			}
		}
		if !hasRequired {
			ff = append(ff, makeFinding(
				finding.CheckTerraformIMDSv1Enabled,
				finding.SeverityHigh,
				fmt.Sprintf("EC2 instance %q does not require IMDSv2 (http_tokens = required)", res.name),
				fmt.Sprintf("Instance %q in %s has a metadata_options block but http_tokens is not set to \"required\". IMDSv1 is vulnerable to SSRF attacks that can steal IAM credentials.", res.name, filepath.Base(path)),
				path, res.lineNo,
				fmt.Sprintf(`resource "aws_instance" "%s" {
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
}`, res.name),
			))
		}
	} else {
		// No metadata_options block at all — IMDSv1 is enabled by default.
		ff = append(ff, makeFinding(
			finding.CheckTerraformIMDSv1Enabled,
			finding.SeverityHigh,
			fmt.Sprintf("EC2 instance %q does not configure metadata_options (IMDSv1 enabled by default)", res.name),
			fmt.Sprintf("Instance %q in %s has no metadata_options block, so IMDSv1 is enabled by default. Add metadata_options with http_tokens = \"required\" to enforce IMDSv2.", res.name, filepath.Base(path)),
			path, res.lineNo,
			fmt.Sprintf(`resource "aws_instance" "%s" {
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
}`, res.name),
		))
	}
	return ff
}

func checkIAMPolicy(path string, res hclResource) []finding.Finding {
	var ff []finding.Finding
	// Look for wildcard Action or Resource in policy JSON (often inlined as heredoc or jsonencode).
	raw := res.attrs["policy"]
	if raw == "" {
		return ff
	}
	// The policy value may contain escaped quotes (\") when the JSON is inlined
	// as a string literal. Normalise to actual quotes for pattern matching.
	rawUnesc := strings.ReplaceAll(raw, `\"`, `"`)
	rawLower := strings.ToLower(rawUnesc)
	if strings.Contains(rawLower, `"action": "*"`) ||
		strings.Contains(rawLower, `"action":"*"`) ||
		strings.Contains(rawLower, `"action":["*"]`) {
		ff = append(ff, makeFinding(
			finding.CheckTerraformIAMWildcardPolicy,
			finding.SeverityHigh,
			fmt.Sprintf("IAM policy %q uses wildcard Action: \"*\"", res.name),
			fmt.Sprintf("The IAM policy %q in %s grants Action: \"*\" which is equivalent to full administrative access. Apply least-privilege by listing only the specific actions required.", res.name, filepath.Base(path)),
			path, res.lineNo, "",
		))
	}
	if strings.Contains(rawLower, `"resource": "*"`) ||
		strings.Contains(rawLower, `"resource":"*"`) {
		if strings.Contains(rawLower, `"action": "*"`) || strings.Contains(rawLower, `"action":"*"`) ||
			strings.Contains(rawLower, `"action":["*"]`) {
			// Already caught above with higher specificity.
			return ff
		}
		ff = append(ff, makeFinding(
			finding.CheckTerraformIAMWildcardPolicy,
			finding.SeverityMedium,
			fmt.Sprintf("IAM policy %q uses wildcard Resource: \"*\"", res.name),
			fmt.Sprintf("The IAM policy %q in %s applies to Resource: \"*\" — consider restricting to specific resource ARNs.", res.name, filepath.Base(path)),
			path, res.lineNo, "",
		))
	}
	return ff
}

// adminPolicyARNs are managed policy ARNs that grant full administrative access.
var adminPolicyARNs = []string{
	"arn:aws:iam::aws:policy/AdministratorAccess",
	"arn:aws:iam::aws:policy/PowerUserAccess",
}

func checkIAMAdminAttachment(path string, res hclResource) []finding.Finding {
	var ff []finding.Finding
	policyARN := res.attrs["policy_arn"]
	for _, arn := range adminPolicyARNs {
		if strings.EqualFold(policyARN, arn) {
			ff = append(ff, makeFinding(
				finding.CheckTerraformIAMAdminPolicy,
				finding.SeverityCritical,
				fmt.Sprintf("Administrative IAM policy attached: %s → %s", res.name, arn),
				fmt.Sprintf("Resource %q in %s attaches the %q managed policy. This grants unrestricted AWS access. Apply a least-privilege custom policy instead.", res.name, filepath.Base(path), arn),
				path, res.lineNo, "",
			))
		}
	}
	return ff
}

func checkECRRepo(path string, res hclResource) []finding.Finding {
	var ff []finding.Finding
	if v := res.attrs["image_tag_mutability"]; v == "" {
		// Missing — default is MUTABLE (allows tag overwrite attacks).
	}
	// Check if encryptionConfiguration is absent or uses default AES256.
	// Primary check: mutability.
	// Also check if the repo is accidentally public via force_delete or
	// if encryption is not set to KMS.
	// Simple public check via aws_ecr_repository_policy is separate.

	// Check encryption type.
	encLines := res.subBlocks["encryption_configuration"]
	if len(encLines) == 0 {
		ff = append(ff, makeFinding(
			finding.CheckTerraformPublicECRRepo,
			finding.SeverityMedium,
			fmt.Sprintf("ECR repository %q does not configure KMS encryption", res.name),
			fmt.Sprintf("The ECR repository %q in %s does not set a KMS encryption configuration. Add encryption_configuration with encryption_type = \"KMS\" for compliance.", res.name, filepath.Base(path)),
			path, res.lineNo,
			fmt.Sprintf(`resource "aws_ecr_repository" "%s" {
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.ecr.arn
  }
}`, res.name),
		))
	}
	return ff
}

func checkCloudFront(path string, res hclResource) []finding.Finding {
	var ff []finding.Finding
	// Check viewer_protocol_policy in default_cache_behavior and ordered_cache_behavior.
	for _, blockName := range []string{"default_cache_behavior", "ordered_cache_behavior"} {
		for _, l := range res.subBlocks[blockName] {
			if k, v, ok := parseAttr(l); ok && k == "viewer_protocol_policy" {
				if v == "allow-all" {
					ff = append(ff, makeFinding(
						finding.CheckTerraformCloudFrontHTTP,
						finding.SeverityMedium,
						fmt.Sprintf("CloudFront distribution %q allows HTTP (viewer_protocol_policy = allow-all)", res.name),
						fmt.Sprintf("The CloudFront distribution %q in %s has viewer_protocol_policy = \"allow-all\", permitting plain HTTP connections. Change to \"https-only\" or \"redirect-to-https\".", res.name, filepath.Base(path)),
						path, res.lineNo,
						fmt.Sprintf(`resource "aws_cloudfront_distribution" "%s" {
  default_cache_behavior {
    viewer_protocol_policy = "redirect-to-https"
  }
}`, res.name),
					))
				}
			}
		}
	}
	return ff
}

func checkLBListener(path string, res hclResource) []finding.Finding {
	var ff []finding.Finding
	protocol := res.attrs["protocol"]
	if strings.ToUpper(protocol) == "HTTP" {
		action := res.attrs["default_action_type"]
		if action == "" {
			// Check sub-block default_action for type.
			for _, l := range res.subBlocks["default_action"] {
				if k, v, ok := parseAttr(l); ok && k == "type" {
					action = v
				}
			}
		}
		if action != "redirect" && action != "redirect_to_https" {
			ff = append(ff, makeFinding(
				finding.CheckTerraformLBHTTP,
				finding.SeverityMedium,
				fmt.Sprintf("Load balancer listener %q uses HTTP without redirect", res.name),
				fmt.Sprintf("The ALB listener %q in %s listens on HTTP without redirecting to HTTPS. Add a redirect action or change the listener to HTTPS.", res.name, filepath.Base(path)),
				path, res.lineNo,
				fmt.Sprintf(`resource "aws_lb_listener" "%s" {
  port     = "80"
  protocol = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}`, res.name),
			))
		}
	}
	return ff
}

// ---- GCP checks --------------------------------------------------------

func checkGCSBucket(path string, res hclResource) []finding.Finding {
	var ff []finding.Finding
	// Check for allUsers / allAuthenticatedUsers in IAM bindings within the resource.
	// These usually appear in separate google_storage_bucket_iam_binding resources,
	// but sometimes are inlined.
	for _, lines := range res.subBlocks {
		for _, l := range lines {
			lower := strings.ToLower(l)
			if strings.Contains(lower, "allusers") || strings.Contains(lower, "allauthenticatedusers") {
				ff = append(ff, makeFinding(
					finding.CheckTerraformGCSBucketPublic,
					finding.SeverityHigh,
					fmt.Sprintf("GCS bucket %q grants access to allUsers or allAuthenticatedUsers", res.name),
					fmt.Sprintf("The GCS bucket %q in %s has an IAM binding granting access to allUsers or allAuthenticatedUsers, making all objects public.", res.name, filepath.Base(path)),
					path, res.lineNo,
					fmt.Sprintf(`# Remove allUsers / allAuthenticatedUsers from bucket IAM:
resource "google_storage_bucket_iam_binding" "%s_private" {
  bucket  = google_storage_bucket.%s.name
  role    = "roles/storage.objectViewer"
  members = []  # empty — no public access
}
resource "google_storage_bucket" "%s" {
  uniform_bucket_level_access = true  # required to remove legacy ACLs
}`, res.name, res.name, res.name),
				))
				break
			}
		}
	}
	// Check uniform_bucket_level_access is enabled.
	if v := res.attrs["uniform_bucket_level_access"]; v == "false" || v == "" {
		if v == "false" {
			ff = append(ff, makeFinding(
				finding.CheckTerraformGCSBucketPublic,
				finding.SeverityMedium,
				fmt.Sprintf("GCS bucket %q has uniform_bucket_level_access = false", res.name),
				fmt.Sprintf("GCS bucket %q in %s has uniform_bucket_level_access disabled, allowing per-object legacy ACLs that can inadvertently make objects public.", res.name, filepath.Base(path)),
				path, res.lineNo,
				fmt.Sprintf(`resource "google_storage_bucket" "%s" {
  uniform_bucket_level_access = true
}`, res.name),
			))
		}
	}
	return ff
}

func checkGKECluster(path string, res hclResource) []finding.Finding {
	var ff []finding.Finding

	// Check for private_cluster_config block.
	privateLines := res.subBlocks["private_cluster_config"]
	hasPrivateEndpoint := false
	for _, l := range privateLines {
		if strings.Contains(l, "enable_private_endpoint") && strings.Contains(l, "true") {
			hasPrivateEndpoint = true
		}
	}

	masterAuthLines := res.subBlocks["master_authorized_networks_config"]
	if len(masterAuthLines) == 0 && !hasPrivateEndpoint {
		ff = append(ff, makeFinding(
			finding.CheckTerraformGKEPublicEndpoint,
			finding.SeverityCritical,
			fmt.Sprintf("GKE cluster %q has public endpoint with no authorized networks", res.name),
			fmt.Sprintf("The GKE cluster %q in %s has a public API endpoint and no master_authorized_networks_config. The Kubernetes API server is reachable from any IP. Add an authorized networks block or enable private endpoint.", res.name, filepath.Base(path)),
			path, res.lineNo,
			fmt.Sprintf(`resource "google_container_cluster" "%s" {
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = true
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }
  # OR restrict access to specific CIDRs:
  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = "10.0.0.0/8"
      display_name = "internal"
    }
  }
}`, res.name),
		))
	}

	// Check legacy ABAC (enable_legacy_abac).
	if v := res.attrs["enable_legacy_abac"]; v == "true" {
		ff = append(ff, makeFinding(
			finding.CheckTerraformGKELegacyABAC,
			finding.SeverityHigh,
			fmt.Sprintf("GKE cluster %q has legacy ABAC enabled", res.name),
			fmt.Sprintf("GKE cluster %q in %s has enable_legacy_abac = true. Legacy ABAC grants overly broad permissions and should be disabled in favour of Kubernetes RBAC.", res.name, filepath.Base(path)),
			path, res.lineNo,
			fmt.Sprintf(`resource "google_container_cluster" "%s" {
  enable_legacy_abac = false
}`, res.name),
		))
	}

	// Check network policy.
	netPolicyLines := res.subBlocks["network_policy"]
	hasNetPolicy := false
	for _, l := range netPolicyLines {
		if strings.Contains(l, "enabled") && strings.Contains(l, "true") {
			hasNetPolicy = true
		}
	}
	if !hasNetPolicy {
		ff = append(ff, makeFinding(
			finding.CheckTerraformGKENoNetworkPolicy,
			finding.SeverityMedium,
			fmt.Sprintf("GKE cluster %q does not enable Kubernetes network policy", res.name),
			fmt.Sprintf("GKE cluster %q in %s has no network_policy block with enabled = true. Without network policies, any pod can communicate with any other pod in the cluster.", res.name, filepath.Base(path)),
			path, res.lineNo,
			fmt.Sprintf(`resource "google_container_cluster" "%s" {
  network_policy {
    enabled  = true
    provider = "CALICO"
  }
  addons_config {
    network_policy_config { disabled = false }
  }
}`, res.name),
		))
	}

	return ff
}

// ---- Secret detection --------------------------------------------------

// secretPatterns matches common credential patterns in attribute values.
var secretPatterns = []struct {
	re    *regexp.Regexp
	label string
}{
	{regexp.MustCompile(`(?i)^(AKIA|ASIA|AROA)[A-Z0-9]{16}$`), "AWS access key"},
	{regexp.MustCompile(`(?i)^sk-[a-zA-Z0-9]{32,}$`), "OpenAI API key"},
	{regexp.MustCompile(`(?i)^ghp_[a-zA-Z0-9]{36}$`), "GitHub personal access token"},
	{regexp.MustCompile(`(?i)^(xox[baprs]-)[a-zA-Z0-9\-]{10,}$`), "Slack token"},
	{regexp.MustCompile(`(?i)^[a-zA-Z0-9+/]{40}$`), "possible AWS secret key (40-char base64)"},
	{regexp.MustCompile(`(?i)password\s*=\s*[^\$\{][^\s]{6,}`), "hardcoded password attribute"},
}

// sensitiveAttrNames are attribute names that should never have literal values.
var sensitiveAttrNames = []string{
	"password", "secret", "api_key", "access_key", "secret_key",
	"private_key", "token", "credential", "auth_token",
}

func checkSecretsInAttrs(path string, res hclResource) []finding.Finding {
	var ff []finding.Finding
	for key, val := range res.attrs {
		keyLower := strings.ToLower(key)
		// Skip values that are clearly Terraform references or variables.
		if strings.HasPrefix(val, "var.") || strings.HasPrefix(val, "${") ||
			strings.HasPrefix(val, "local.") || strings.HasPrefix(val, "data.") ||
			strings.HasPrefix(val, "module.") || val == "" || val == "null" {
			continue
		}
		for _, sensitive := range sensitiveAttrNames {
			if strings.Contains(keyLower, sensitive) && len(val) > 4 {
				ff = append(ff, makeFinding(
					finding.CheckTerraformSecretsInCode,
					finding.SeverityCritical,
					fmt.Sprintf("Possible hardcoded secret in %s.%s attribute %q", res.resourceType, res.name, key),
					fmt.Sprintf("The attribute %q in resource %q (%s:%d) appears to contain a hardcoded secret value. Use a variable, AWS Secrets Manager, or Vault reference instead: var.%s, data.aws_secretsmanager_secret_version.x.secret_string, etc.", key, res.name, filepath.Base(path), res.lineNo, key),
					path, res.lineNo,
					fmt.Sprintf(`# Replace hardcoded value with a variable or secrets manager reference:
variable "%s" {
  description = "The %s — do not hardcode"
  type        = string
  sensitive   = true
}
# Or use AWS Secrets Manager:
data "aws_secretsmanager_secret_version" "creds" {
  secret_id = "my-secret-name"
}`, key, key),
				))
				break
			}
		}
		// Also scan values for credential patterns.
		for _, sp := range secretPatterns {
			if sp.re.MatchString(val) {
				ff = append(ff, makeFinding(
					finding.CheckTerraformSecretsInCode,
					finding.SeverityCritical,
					fmt.Sprintf("Detected %s hardcoded in %s.%s", sp.label, res.resourceType, res.name),
					fmt.Sprintf("A %s pattern was detected in resource %q (%s:%d). Remove from Terraform code and use a secrets manager reference or environment variable.", sp.label, res.name, filepath.Base(path), res.lineNo),
					path, res.lineNo, "",
				))
				break
			}
		}
	}
	return ff
}

// ---- Terraform state backend check ------------------------------------

func checkTFState(hf *hclFile) []finding.Finding {
	backendType, _ := hf.globals["backend.type"]
	if backendType == "s3" {
		// Check if encrypt = false.
		if v := hf.globals["backend.encrypt"]; v == "false" {
			return []finding.Finding{makeFinding(
				finding.CheckTerraformTFStatePublic,
				finding.SeverityHigh,
				"Terraform S3 backend has encrypt = false",
				fmt.Sprintf("The Terraform S3 backend in %s has encrypt = false. State files contain all resource attribute values including secrets and should always be encrypted at rest.", filepath.Base(hf.path)),
				hf.path, 0,
				`terraform {
  backend "s3" {
    bucket  = "my-terraform-state"
    key     = "prod/terraform.tfstate"
    region  = "us-east-1"
    encrypt = true
    kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/my-key-id"
  }
}`,
			)}
		}
	}
	return nil
}

// ---- helpers -----------------------------------------------------------

func makeFinding(checkID finding.CheckID, sev finding.Severity, title, desc, path string, lineNo int, tfFix string) finding.Finding {
	asset := path
	if lineNo > 0 {
		asset = fmt.Sprintf("%s:%d", path, lineNo)
	}
	return finding.Finding{
		CheckID:      checkID,
		Module:       "terraform",
		Scanner:      "terraform",
		Severity:     sev,
		Title:        title,
		Description:  desc,
		Asset:        asset,
		ProofCommand: fmt.Sprintf("grep -n . %q | head -30", path),
		Evidence: map[string]any{
			"file":         path,
			"line":         lineNo,
			"terraform_fix": tfFix,
		},
		DiscoveredAt: time.Now(),
	}
}
