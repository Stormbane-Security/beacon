package aws

import "testing"

// ---------------------------------------------------------------------------
// Scanner.Name() — verifies the scanner identifier
// ---------------------------------------------------------------------------

func TestScannerName(t *testing.T) {
	s := New(Config{})
	if got := s.Name(); got != "cloud/aws" {
		t.Errorf("Scanner.Name() = %q, want %q", got, "cloud/aws")
	}
}

// ---------------------------------------------------------------------------
// New — constructor returns a scanner with the given config
// ---------------------------------------------------------------------------

func TestNew_PreservesConfig(t *testing.T) {
	cfg := Config{
		Profile:   "prod-security",
		Region:    "eu-west-1",
		RoleARN:   "arn:aws:iam::123456789012:role/SecurityAudit",
		AccountID: "123456789012",
	}
	s := New(cfg)
	if s.cfg.Profile != cfg.Profile {
		t.Errorf("Profile = %q, want %q", s.cfg.Profile, cfg.Profile)
	}
	if s.cfg.Region != cfg.Region {
		t.Errorf("Region = %q, want %q", s.cfg.Region, cfg.Region)
	}
	if s.cfg.RoleARN != cfg.RoleARN {
		t.Errorf("RoleARN = %q, want %q", s.cfg.RoleARN, cfg.RoleARN)
	}
	if s.cfg.AccountID != cfg.AccountID {
		t.Errorf("AccountID = %q, want %q", s.cfg.AccountID, cfg.AccountID)
	}
}

func TestNew_EmptyConfig(t *testing.T) {
	s := New(Config{})
	if s.cfg.Profile != "" {
		t.Errorf("Profile = %q, want empty", s.cfg.Profile)
	}
	if s.cfg.Region != "" {
		t.Errorf("Region = %q, want empty", s.cfg.Region)
	}
	if s.cfg.RoleARN != "" {
		t.Errorf("RoleARN = %q, want empty", s.cfg.RoleARN)
	}
	if s.cfg.AccountID != "" {
		t.Errorf("AccountID = %q, want empty", s.cfg.AccountID)
	}
}

// ---------------------------------------------------------------------------
// Config default region — the Run method defaults to us-east-1 when empty.
// We can't call Run without AWS credentials, but we can verify the Config
// struct stores empty vs non-empty region correctly.
// ---------------------------------------------------------------------------

func TestConfig_RegionDefault(t *testing.T) {
	tests := []struct {
		name     string
		region   string
		wantCfg  string
	}{
		{"empty region stored as empty", "", ""},
		{"explicit region preserved", "ap-southeast-1", "ap-southeast-1"},
		{"us-east-1 preserved", "us-east-1", "us-east-1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New(Config{Region: tt.region})
			if s.cfg.Region != tt.wantCfg {
				t.Errorf("cfg.Region = %q, want %q", s.cfg.Region, tt.wantCfg)
			}
		})
	}
}
