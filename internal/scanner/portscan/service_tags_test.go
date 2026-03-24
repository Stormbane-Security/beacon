package portscan

import (
	"testing"
)

func TestServiceNucleiTagsEmpty(t *testing.T) {
	tags := ServiceNucleiTags(nil)
	if len(tags) != 0 {
		t.Errorf("expected empty tags for nil ports, got %v", tags)
	}
	tags = ServiceNucleiTags(map[int]string{})
	if len(tags) != 0 {
		t.Errorf("expected empty tags for empty ports, got %v", tags)
	}
}

func TestServiceNucleiTagsKnownPorts(t *testing.T) {
	ports := map[int]string{
		6379: "redis",
		9200: "elasticsearch",
	}
	tags := ServiceNucleiTags(ports)
	tagSet := make(map[string]bool, len(tags))
	for _, t := range tags {
		tagSet[t] = true
	}
	if !tagSet["redis"] {
		t.Error("expected redis tag for port 6379")
	}
	if !tagSet["elasticsearch"] {
		t.Error("expected elasticsearch tag for port 9200")
	}
}

func TestServiceNucleiTagsDeduplication(t *testing.T) {
	// Ports 9090 and 9091 both map to "prometheus" — should appear only once.
	ports := map[int]string{
		9090: "prometheus",
		9091: "prometheus-pushgateway",
	}
	tags := ServiceNucleiTags(ports)
	count := 0
	for _, tag := range tags {
		if tag == "prometheus" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("prometheus tag appeared %d times; want exactly 1", count)
	}
}

func TestServiceNucleiTagsUnknownPort(t *testing.T) {
	// Port 12345 is not in the map — no tags should be emitted.
	ports := map[int]string{12345: "unknown"}
	tags := ServiceNucleiTags(ports)
	if len(tags) != 0 {
		t.Errorf("expected no tags for unknown port, got %v", tags)
	}
}

func TestServiceNucleiTagsMultiTagPort(t *testing.T) {
	// Port 10250 maps to both "kubernetes" and "kubelet".
	ports := map[int]string{10250: "kubelet"}
	tags := ServiceNucleiTags(ports)
	tagSet := make(map[string]bool, len(tags))
	for _, tag := range tags {
		tagSet[tag] = true
	}
	if !tagSet["kubernetes"] {
		t.Error("expected kubernetes tag for port 10250")
	}
	if !tagSet["kubelet"] {
		t.Error("expected kubelet tag for port 10250")
	}
	if len(tags) != 2 {
		t.Errorf("expected 2 tags for port 10250, got %d: %v", len(tags), tags)
	}
}

func TestServiceNucleiTagsMixedKnownUnknown(t *testing.T) {
	ports := map[int]string{
		6379:  "redis",   // known → "redis"
		99999: "mystery", // unknown → no tags
	}
	tags := ServiceNucleiTags(ports)
	if len(tags) != 1 || tags[0] != "redis" {
		t.Errorf("expected [redis], got %v", tags)
	}
}

// TestAllKnownPortsUnique verifies that AllKnownPorts returns no duplicates.
func TestAllKnownPortsUnique(t *testing.T) {
	seen := make(map[int]bool)
	for _, p := range AllKnownPorts() {
		if seen[p] {
			t.Errorf("port %d appears more than once in AllKnownPorts()", p)
		}
		seen[p] = true
	}
}

// TestAllKnownPortsNonEmpty verifies that the static list is populated.
func TestAllKnownPortsNonEmpty(t *testing.T) {
	if len(AllKnownPorts()) == 0 {
		t.Error("AllKnownPorts() returned empty list")
	}
}
