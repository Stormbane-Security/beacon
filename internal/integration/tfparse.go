package integration

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/stormbane/beacon/internal/project"
)

// resourceBlockRe matches HCL resource blocks: resource "type" "name" {
var resourceBlockRe = regexp.MustCompile(`(?m)^resource\s+"([^"]+)"\s+"([^"]+)"\s*\{`)

// dataBlockRe matches HCL data blocks: data "type" "name" {
var dataBlockRe = regexp.MustCompile(`(?m)^data\s+"([^"]+)"\s+"([^"]+)"\s*\{`)

// moduleBlockRe matches HCL module blocks: module "name" {
var moduleBlockRe = regexp.MustCompile(`(?m)^module\s+"([^"]+)"\s*\{`)

// providerBlockRe matches provider blocks to detect which providers are configured.
var providerBlockRe = regexp.MustCompile(`(?m)^provider\s+"([^"]+)"\s*\{`)

// variableRe matches variable blocks with defaults: variable "name" { default = "value" }
var variableRe = regexp.MustCompile(`(?m)^variable\s+"([^"]+)"\s*\{`)

// providerMap maps Terraform provider prefixes to cloud providers.
var providerMap = map[string]string{
	"google":  "gcp",
	"aws":     "aws",
	"azurerm": "azure",
	"azuread": "azure",
	"helm":    "kubernetes",
	"kubernetes": "kubernetes",
	"random":  "utility",
	"null":    "utility",
	"local":   "utility",
	"tls":     "utility",
	"github":  "github",
	"okta":    "okta",
}

// ParseHCL extracts resource definitions from Terraform HCL content.
// This is a lightweight regex-based parser — it doesn't parse the full HCL AST
// but reliably extracts resource types, names, and provider info.
func ParseHCL(content string) []project.Resource {
	var resources []project.Resource

	// Extract resource blocks.
	for _, m := range resourceBlockRe.FindAllStringSubmatch(content, -1) {
		resType := m[1]
		resName := m[2]
		provider := providerFromType(resType)
		resources = append(resources, project.Resource{
			ID:       resType + "." + resName,
			Type:     resType,
			Name:     resName,
			Provider: provider,
			Source:   "terraform",
			Managed:  true,
		})
	}

	// Extract module blocks.
	for _, m := range moduleBlockRe.FindAllStringSubmatch(content, -1) {
		resources = append(resources, project.Resource{
			ID:       "module." + m[1],
			Type:     "module",
			Name:     m[1],
			Provider: "unknown",
			Source:   "terraform",
			Managed:  true,
		})
	}

	return resources
}

// providerFromType extracts the provider from a resource type string.
// e.g. "google_container_cluster" → "gcp", "aws_s3_bucket" → "aws"
func providerFromType(resType string) string {
	parts := strings.SplitN(resType, "_", 2)
	if len(parts) == 0 {
		return "unknown"
	}
	if p, ok := providerMap[parts[0]]; ok {
		return p
	}
	return parts[0]
}

// TFState is the top-level Terraform state JSON structure.
type TFState struct {
	Version   int              `json:"version"`
	Resources []TFStateResource `json:"resources"`
}

// TFStateResource is a resource entry in the Terraform state.
type TFStateResource struct {
	Mode      string           `json:"mode"` // "managed" or "data"
	Type      string           `json:"type"`
	Name      string           `json:"name"`
	Provider  string           `json:"provider"`
	Instances []TFStateInstance `json:"instances"`
}

// TFStateInstance holds the attributes of a resource instance.
type TFStateInstance struct {
	Attributes    map[string]any `json:"attributes"`
	AttributesRaw json.RawMessage `json:"attributes_flat"`
}

// ParseTFState parses a terraform.tfstate JSON file and returns resources.
func ParseTFState(content string) []project.Resource {
	var state TFState
	if err := json.Unmarshal([]byte(content), &state); err != nil {
		return nil
	}

	var resources []project.Resource
	for _, r := range state.Resources {
		if r.Mode != "managed" {
			continue // skip data sources
		}

		provider := providerFromType(r.Type)
		attrs := extractKeyAttrs(r)

		resources = append(resources, project.Resource{
			ID:       r.Type + "." + r.Name,
			Type:     r.Type,
			Name:     r.Name,
			Provider: provider,
			Source:   "terraform_state",
			Managed:  true,
			Attrs:    attrs,
		})
	}
	return resources
}

// extractKeyAttrs pulls useful attributes from the first instance of a resource.
func extractKeyAttrs(r TFStateResource) map[string]string {
	if len(r.Instances) == 0 {
		return nil
	}
	attrs := r.Instances[0].Attributes
	if attrs == nil {
		return nil
	}

	keyFields := []string{
		"name", "id", "region", "zone", "location", "project",
		"arn", "bucket", "cluster_name", "network", "cidr_block",
		"vpc_id", "subnet_id", "resource_group_name",
	}

	out := make(map[string]string)
	for _, k := range keyFields {
		if v, ok := attrs[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				out[k] = s
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
