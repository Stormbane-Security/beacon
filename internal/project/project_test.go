package project

import (
	"testing"
)

func TestStore_CreateAndGet(t *testing.T) {
	s := NewStore()
	p := &Project{Name: "test-project", Domains: []string{"example.com"}}
	if err := s.Create(p); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if p.ID == "" {
		t.Fatal("expected ID to be assigned")
	}

	got, ok := s.Get(p.ID)
	if !ok {
		t.Fatal("expected project to be found")
	}
	if got.Name != "test-project" {
		t.Errorf("expected name 'test-project', got %q", got.Name)
	}
}

func TestStore_List(t *testing.T) {
	s := NewStore()
	s.Create(&Project{Name: "a"})
	s.Create(&Project{Name: "b"})
	if len(s.List()) != 2 {
		t.Errorf("expected 2 projects, got %d", len(s.List()))
	}
}

func TestStore_Update(t *testing.T) {
	s := NewStore()
	p := &Project{Name: "old"}
	s.Create(p)
	p.Name = "new"
	if err := s.Update(p); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, _ := s.Get(p.ID)
	if got.Name != "new" {
		t.Errorf("expected 'new', got %q", got.Name)
	}
}

func TestStore_Delete(t *testing.T) {
	s := NewStore()
	p := &Project{Name: "doomed"}
	s.Create(p)
	if err := s.Delete(p.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := s.Get(p.ID); ok {
		t.Fatal("expected project to be deleted")
	}
}

func TestStore_AddIntegration(t *testing.T) {
	s := NewStore()
	p := &Project{Name: "proj"}
	s.Create(p)

	intg := Integration{Type: IntegrationGitHub, Name: "org/repo"}
	if err := s.AddIntegration(p.ID, intg); err != nil {
		t.Fatalf("AddIntegration: %v", err)
	}

	got, _ := s.Get(p.ID)
	if len(got.Integrations) != 1 {
		t.Fatalf("expected 1 integration, got %d", len(got.Integrations))
	}
	if got.Integrations[0].Name != "org/repo" {
		t.Errorf("expected 'org/repo', got %q", got.Integrations[0].Name)
	}
}

func TestStore_RemoveIntegration(t *testing.T) {
	s := NewStore()
	p := &Project{Name: "proj"}
	s.Create(p)

	intg := Integration{ID: "int1", Type: IntegrationGitHub, Name: "org/repo"}
	s.AddIntegration(p.ID, intg)

	if err := s.RemoveIntegration(p.ID, "int1"); err != nil {
		t.Fatalf("RemoveIntegration: %v", err)
	}
	got, _ := s.Get(p.ID)
	if len(got.Integrations) != 0 {
		t.Errorf("expected 0 integrations, got %d", len(got.Integrations))
	}
}

func TestStore_AddPlan(t *testing.T) {
	s := NewStore()
	p := &Project{Name: "proj"}
	s.Create(p)

	plan := Plan{
		Name: "prod plan",
		Items: []PlanItem{
			{CatalogID: "gcp-gke-cluster", Params: map[string]string{"cluster_name": "prod"}},
		},
		SharedVars: map[string]string{"project_id": "my-proj", "region": "us-central1"},
	}
	if err := s.AddPlan(p.ID, plan); err != nil {
		t.Fatalf("AddPlan: %v", err)
	}

	got, _ := s.Get(p.ID)
	if len(got.Plans) != 1 {
		t.Fatalf("expected 1 plan, got %d", len(got.Plans))
	}
	if got.Plans[0].Name != "prod plan" {
		t.Errorf("expected 'prod plan', got %q", got.Plans[0].Name)
	}
	if got.Plans[0].SharedVars["region"] != "us-central1" {
		t.Error("expected shared var region=us-central1")
	}
}

func TestStore_BuildContext(t *testing.T) {
	s := NewStore()
	p := &Project{Name: "proj", Domains: []string{"example.com"}}
	s.Create(p)

	intg := Integration{
		ID:   "int1",
		Type: IntegrationGitHub,
		Name: "org/infra",
		Resources: []Resource{
			{Type: "google_container_cluster", Name: "prod", Provider: "gcp", Source: "terraform", Managed: true},
			{Type: "google_compute_instance", Name: "bastion", Provider: "gcp", Source: "terraform", Managed: true},
		},
	}
	s.AddIntegration(p.ID, intg)

	intg2 := Integration{
		ID:   "int2",
		Type: IntegrationGCP,
		Name: "my-project",
		Resources: []Resource{
			{Type: "google_container_cluster", Name: "prod", Provider: "gcp", Source: "cloud_api", Managed: false},
			{Type: "google_sql_database_instance", Name: "main-db", Provider: "gcp", Source: "cloud_api", Managed: false},
		},
	}
	s.AddIntegration(p.ID, intg2)

	ctx, err := s.BuildContext(p.ID)
	if err != nil {
		t.Fatalf("BuildContext: %v", err)
	}

	if len(ctx.ExistingResources) != 4 {
		t.Errorf("expected 4 existing resources, got %d", len(ctx.ExistingResources))
	}
	if len(ctx.ManagedResources) != 2 {
		t.Errorf("expected 2 managed resources, got %d", len(ctx.ManagedResources))
	}
	// The SQL instance is unmanaged — in cloud but not in terraform.
	if len(ctx.UnmanagedGaps) != 1 {
		t.Errorf("expected 1 unmanaged gap, got %d", len(ctx.UnmanagedGaps))
	}
	if len(ctx.UnmanagedGaps) > 0 && ctx.UnmanagedGaps[0].Name != "main-db" {
		t.Errorf("expected unmanaged gap 'main-db', got %q", ctx.UnmanagedGaps[0].Name)
	}
}
