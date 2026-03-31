package gcp

import "testing"

func TestNew(t *testing.T) {
	cfg := Config{
		ProjectIDs:            []string{"proj-1", "proj-2"},
		ServiceAccountKeyFile: "/path/to/key.json",
	}
	s := New(cfg)
	if s == nil {
		t.Fatal("New returned nil")
	}
	if s.cfg.ServiceAccountKeyFile != "/path/to/key.json" {
		t.Errorf("ServiceAccountKeyFile = %q; want /path/to/key.json", s.cfg.ServiceAccountKeyFile)
	}
	if len(s.cfg.ProjectIDs) != 2 {
		t.Errorf("len(ProjectIDs) = %d; want 2", len(s.cfg.ProjectIDs))
	}
}

func TestName(t *testing.T) {
	s := New(Config{})
	if s.Name() != "cloud/gcp" {
		t.Errorf("Name() = %q; want cloud/gcp", s.Name())
	}
}

func TestClientOptions_WithKeyFile(t *testing.T) {
	s := New(Config{ServiceAccountKeyFile: "/path/to/key.json"})
	opts := s.clientOptions()
	if len(opts) != 1 {
		t.Errorf("len(clientOptions) = %d; want 1 when key file is set", len(opts))
	}
}

func TestClientOptions_WithoutKeyFile(t *testing.T) {
	s := New(Config{})
	opts := s.clientOptions()
	if opts != nil {
		t.Errorf("clientOptions = %v; want nil when no key file set", opts)
	}
}
