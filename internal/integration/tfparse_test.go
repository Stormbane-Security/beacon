package integration

import (
	"testing"
)

func TestParseHCL_Resources(t *testing.T) {
	hcl := `
resource "google_container_cluster" "primary" {
  name     = "my-cluster"
  location = "us-central1"
}

resource "google_compute_network" "vpc" {
  name = "main-vpc"
}

resource "aws_s3_bucket" "logs" {
  bucket = "my-logs"
}

module "gke_auth" {
  source = "terraform-google-modules/kubernetes-engine/google//modules/auth"
}
`
	resources := ParseHCL(hcl)
	if len(resources) != 4 { // 3 resources + 1 module
		t.Fatalf("expected 4 resources, got %d", len(resources))
	}

	// Check first resource.
	r := resources[0]
	if r.Type != "google_container_cluster" {
		t.Errorf("expected type 'google_container_cluster', got %q", r.Type)
	}
	if r.Name != "primary" {
		t.Errorf("expected name 'primary', got %q", r.Name)
	}
	if r.Provider != "gcp" {
		t.Errorf("expected provider 'gcp', got %q", r.Provider)
	}
	if !r.Managed {
		t.Error("expected managed=true for terraform resources")
	}

	// Check AWS resource.
	r2 := resources[2]
	if r2.Provider != "aws" {
		t.Errorf("expected provider 'aws', got %q", r2.Provider)
	}

	// Check module.
	r3 := resources[3]
	if r3.Type != "module" {
		t.Errorf("expected type 'module', got %q", r3.Type)
	}
	if r3.Name != "gke_auth" {
		t.Errorf("expected name 'gke_auth', got %q", r3.Name)
	}
}

func TestParseHCL_Empty(t *testing.T) {
	resources := ParseHCL("")
	if len(resources) != 0 {
		t.Errorf("expected 0 resources, got %d", len(resources))
	}
}

func TestParseTFState(t *testing.T) {
	state := `{
		"version": 4,
		"resources": [
			{
				"mode": "managed",
				"type": "google_container_cluster",
				"name": "primary",
				"provider": "provider[\"registry.terraform.io/hashicorp/google\"]",
				"instances": [{
					"attributes": {
						"name": "my-cluster",
						"location": "us-central1",
						"project": "my-project"
					}
				}]
			},
			{
				"mode": "data",
				"type": "google_project",
				"name": "project",
				"provider": "provider[\"registry.terraform.io/hashicorp/google\"]",
				"instances": [{}]
			},
			{
				"mode": "managed",
				"type": "aws_s3_bucket",
				"name": "logs",
				"provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
				"instances": [{
					"attributes": {
						"bucket": "my-logs-bucket",
						"region": "us-east-1"
					}
				}]
			}
		]
	}`

	resources := ParseTFState(state)
	// Should skip the data source, keep 2 managed resources.
	if len(resources) != 2 {
		t.Fatalf("expected 2 resources, got %d", len(resources))
	}

	r := resources[0]
	if r.Type != "google_container_cluster" {
		t.Errorf("expected type 'google_container_cluster', got %q", r.Type)
	}
	if r.Provider != "gcp" {
		t.Errorf("expected provider 'gcp', got %q", r.Provider)
	}
	if r.Attrs["location"] != "us-central1" {
		t.Errorf("expected location attr 'us-central1', got %q", r.Attrs["location"])
	}
	if r.Attrs["project"] != "my-project" {
		t.Errorf("expected project attr 'my-project', got %q", r.Attrs["project"])
	}
	if r.Source != "terraform_state" {
		t.Errorf("expected source 'terraform_state', got %q", r.Source)
	}

	r2 := resources[1]
	if r2.Provider != "aws" {
		t.Errorf("expected provider 'aws', got %q", r2.Provider)
	}
	if r2.Attrs["bucket"] != "my-logs-bucket" {
		t.Errorf("expected bucket attr 'my-logs-bucket', got %q", r2.Attrs["bucket"])
	}
}

func TestParseTFState_Invalid(t *testing.T) {
	resources := ParseTFState("not json")
	if len(resources) != 0 {
		t.Errorf("expected 0 resources for invalid JSON, got %d", len(resources))
	}
}

func TestProviderFromType(t *testing.T) {
	tests := []struct {
		resType  string
		expected string
	}{
		{"google_container_cluster", "gcp"},
		{"aws_s3_bucket", "aws"},
		{"azurerm_kubernetes_cluster", "azure"},
		{"helm_release", "kubernetes"},
		{"random_password", "utility"},
		{"unknown_thing", "unknown"},
	}
	for _, tt := range tests {
		got := providerFromType(tt.resType)
		if got != tt.expected {
			t.Errorf("providerFromType(%q) = %q, want %q", tt.resType, got, tt.expected)
		}
	}
}
