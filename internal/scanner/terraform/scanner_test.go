package terraform_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/scanner/terraform"
)

// writeFile creates a temp .tf file with the given content and returns its path.
func writeFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "main.tf")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// findingByCheckID returns the first finding with the given check ID, or nil.
func findingByCheckID(findings []finding.Finding, id finding.CheckID) *finding.Finding {
	for i := range findings {
		if findings[i].CheckID == id {
			return &findings[i]
		}
	}
	return nil
}

func TestS3Bucket_PublicACL(t *testing.T) {
	path := writeFile(t, `
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  acl    = "public-read"
}
`)
	findings, err := terraform.ScanFiles([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	f := findingByCheckID(findings, finding.CheckTerraformS3BucketPublic)
	if f == nil {
		t.Fatal("expected CheckTerraformS3BucketPublic finding for public-read ACL, got none")
	}
	if f.Severity != finding.SeverityHigh {
		t.Errorf("severity = %s; want High", f.Severity)
	}
}

func TestS3Bucket_PrivateACL_NoFinding(t *testing.T) {
	path := writeFile(t, `
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  acl    = "private"
}
`)
	findings, err := terraform.ScanFiles([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	f := findingByCheckID(findings, finding.CheckTerraformS3BucketPublic)
	if f != nil {
		t.Errorf("did not expect CheckTerraformS3BucketPublic for private ACL, got: %s", f.Title)
	}
}

func TestS3PublicAccessBlock_False(t *testing.T) {
	path := writeFile(t, `
resource "aws_s3_bucket_public_access_block" "main" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = false
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
`)
	findings, err := terraform.ScanFiles([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	f := findingByCheckID(findings, finding.CheckTerraformS3BucketPublic)
	if f == nil {
		t.Fatal("expected CheckTerraformS3BucketPublic for block_public_acls=false, got none")
	}
}

func TestSecurityGroup_OpenIngress(t *testing.T) {
	path := writeFile(t, `
resource "aws_security_group" "web" {
  name = "web-sg"
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`)
	findings, err := terraform.ScanFiles([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	f := findingByCheckID(findings, finding.CheckTerraformSGOpenIngress)
	if f == nil {
		t.Fatal("expected CheckTerraformSGOpenIngress for 0.0.0.0/0, got none")
	}
}

func TestSecurityGroup_RestrictedIngress_NoFinding(t *testing.T) {
	path := writeFile(t, `
resource "aws_security_group" "internal" {
  name = "internal-sg"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
`)
	findings, err := terraform.ScanFiles([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	f := findingByCheckID(findings, finding.CheckTerraformSGOpenIngress)
	if f != nil {
		t.Errorf("did not expect CheckTerraformSGOpenIngress for restricted CIDR, got: %s", f.Title)
	}
}

func TestRDSInstance_PubliclyAccessible(t *testing.T) {
	path := writeFile(t, `
resource "aws_db_instance" "main" {
  engine               = "mysql"
  publicly_accessible  = true
  storage_encrypted    = true
}
`)
	findings, err := terraform.ScanFiles([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	f := findingByCheckID(findings, finding.CheckTerraformRDSPublic)
	if f == nil {
		t.Fatal("expected CheckTerraformRDSPublic for publicly_accessible=true, got none")
	}
	if f.Severity != finding.SeverityCritical {
		t.Errorf("severity = %s; want Critical", f.Severity)
	}
}

func TestRDSInstance_Unencrypted(t *testing.T) {
	path := writeFile(t, `
resource "aws_db_instance" "main" {
  engine              = "postgres"
  publicly_accessible = false
  storage_encrypted   = false
}
`)
	findings, err := terraform.ScanFiles([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	f := findingByCheckID(findings, finding.CheckTerraformRDSUnencrypted)
	if f == nil {
		t.Fatal("expected CheckTerraformRDSUnencrypted for storage_encrypted=false, got none")
	}
}

func TestEC2Instance_IMDSv1_NoMetadataBlock(t *testing.T) {
	path := writeFile(t, `
resource "aws_instance" "app" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
}
`)
	findings, err := terraform.ScanFiles([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	f := findingByCheckID(findings, finding.CheckTerraformIMDSv1Enabled)
	if f == nil {
		t.Fatal("expected CheckTerraformIMDSv1Enabled when metadata_options is absent, got none")
	}
}

func TestEC2Instance_IMDSv2Required_NoFinding(t *testing.T) {
	path := writeFile(t, `
resource "aws_instance" "app" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
}
`)
	findings, err := terraform.ScanFiles([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	f := findingByCheckID(findings, finding.CheckTerraformIMDSv1Enabled)
	if f != nil {
		t.Errorf("did not expect CheckTerraformIMDSv1Enabled when http_tokens=required, got: %s", f.Title)
	}
}

func TestGKECluster_PublicEndpoint(t *testing.T) {
	path := writeFile(t, `
resource "google_container_cluster" "primary" {
  name     = "my-cluster"
  location = "us-central1"
}
`)
	findings, err := terraform.ScanFiles([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	f := findingByCheckID(findings, finding.CheckTerraformGKEPublicEndpoint)
	if f == nil {
		t.Fatal("expected CheckTerraformGKEPublicEndpoint when no authorized networks configured, got none")
	}
	if f.Severity != finding.SeverityCritical {
		t.Errorf("severity = %s; want Critical", f.Severity)
	}
}

func TestGKECluster_LegacyABAC(t *testing.T) {
	path := writeFile(t, `
resource "google_container_cluster" "primary" {
  name               = "my-cluster"
  enable_legacy_abac = true
  master_authorized_networks_config {
    cidr_blocks {
      cidr_block = "10.0.0.0/8"
    }
  }
}
`)
	findings, err := terraform.ScanFiles([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	f := findingByCheckID(findings, finding.CheckTerraformGKELegacyABAC)
	if f == nil {
		t.Fatal("expected CheckTerraformGKELegacyABAC for enable_legacy_abac=true, got none")
	}
}

func TestHardcodedSecret_PasswordAttr(t *testing.T) {
	path := writeFile(t, `
resource "aws_db_instance" "main" {
  engine   = "mysql"
  password = "Sup3rS3cret!"
  storage_encrypted = true
}
`)
	findings, err := terraform.ScanFiles([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	f := findingByCheckID(findings, finding.CheckTerraformSecretsInCode)
	if f == nil {
		t.Fatal("expected CheckTerraformSecretsInCode for hardcoded password, got none")
	}
	if f.Severity != finding.SeverityCritical {
		t.Errorf("severity = %s; want Critical", f.Severity)
	}
}

func TestHardcodedSecret_VarReference_NoFinding(t *testing.T) {
	path := writeFile(t, `
resource "aws_db_instance" "main" {
  engine   = "mysql"
  password = var.db_password
  storage_encrypted = true
}
`)
	findings, err := terraform.ScanFiles([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	f := findingByCheckID(findings, finding.CheckTerraformSecretsInCode)
	if f != nil {
		t.Errorf("did not expect CheckTerraformSecretsInCode for var reference, got: %s", f.Title)
	}
}

func TestDirectoryRecursion(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "modules", "network")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Write a .tf file with a vulnerability in a subdirectory.
	if err := os.WriteFile(filepath.Join(subdir, "sg.tf"), []byte(`
resource "aws_security_group" "open" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
  }
}
`), 0o644); err != nil {
		t.Fatal(err)
	}

	findings, err := terraform.ScanFiles([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	f := findingByCheckID(findings, finding.CheckTerraformSGOpenIngress)
	if f == nil {
		t.Fatal("expected CheckTerraformSGOpenIngress from subdirectory scan, got none")
	}
}

func TestIAMWildcardPolicy(t *testing.T) {
	path := writeFile(t, `
resource "aws_iam_role_policy" "admin" {
  name = "admin-policy"
  role = aws_iam_role.main.id
  policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Action\":\"*\",\"Resource\":\"*\",\"Effect\":\"Allow\"}]}"
}
`)
	findings, err := terraform.ScanFiles([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	f := findingByCheckID(findings, finding.CheckTerraformIAMWildcardPolicy)
	if f == nil {
		t.Fatal("expected CheckTerraformIAMWildcardPolicy for Action:*, got none")
	}
}

func TestCloudFrontHTTPAllowed(t *testing.T) {
	path := writeFile(t, `
resource "aws_cloudfront_distribution" "cdn" {
  default_cache_behavior {
    viewer_protocol_policy = "allow-all"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "main"
  }
}
`)
	findings, err := terraform.ScanFiles([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	f := findingByCheckID(findings, finding.CheckTerraformCloudFrontHTTP)
	if f == nil {
		t.Fatal("expected CheckTerraformCloudFrontHTTP for viewer_protocol_policy=allow-all, got none")
	}
}
