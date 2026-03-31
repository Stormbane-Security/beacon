// Package project provides the workspace model that groups scans, integrations,
// and infrastructure plans into a unified context for AI-driven planning.
package project

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// IntegrationType identifies the kind of external system linked to a project.
type IntegrationType string

const (
	IntegrationGitHub IntegrationType = "github"
	IntegrationGCP    IntegrationType = "gcp"
	IntegrationAWS    IntegrationType = "aws"
	IntegrationAzure  IntegrationType = "azure"
)

// Integration represents a linked external system (GitHub repo, cloud account).
type Integration struct {
	ID        string          `json:"id"`
	Type      IntegrationType `json:"type"`
	Name      string          `json:"name"`      // e.g. "org/repo" or "my-gcp-project"
	Config    map[string]string `json:"config"`   // credentials/settings (token, project_id, etc.)
	Status    string          `json:"status"`     // "connected", "syncing", "error"
	LastSync  *time.Time      `json:"last_sync,omitempty"`
	Resources []Resource      `json:"resources,omitempty"`
	Error     string          `json:"error,omitempty"`
}

// Resource is a discovered infrastructure resource from any source:
// Terraform files, cloud APIs, or Beacon scans.
type Resource struct {
	ID       string            `json:"id"`
	Type     string            `json:"type"`      // e.g. "google_container_cluster", "aws_s3_bucket"
	Name     string            `json:"name"`      // resource name or identifier
	Provider string            `json:"provider"`  // "gcp", "aws", "azure", "unknown"
	Source   string            `json:"source"`     // "terraform", "cloud_api", "scan"
	FilePath string            `json:"file_path,omitempty"` // for terraform resources
	Attrs    map[string]string `json:"attrs,omitempty"`     // key attributes (region, zone, etc.)
	Managed  bool              `json:"managed"`   // true if found in Terraform
}

// PlanItem represents one piece of infrastructure in a consolidated plan.
type PlanItem struct {
	CatalogID   string            `json:"catalog_id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Params      map[string]string `json:"params"`
	DependsOn   []string          `json:"depends_on,omitempty"` // other PlanItem CatalogIDs
	Status      string            `json:"status"`               // "planned", "generated", "applied"
	Files       map[string]string `json:"files,omitempty"`      // generated Terraform files
}

// Plan is a consolidated infrastructure plan with cross-referenced resources.
type Plan struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Items       []PlanItem        `json:"items"`
	SharedVars  map[string]string `json:"shared_vars"` // variables shared across items
	CreatedAt   time.Time         `json:"created_at"`
}

// Project is the top-level workspace grouping scans, integrations, and plans.
type Project struct {
	ID           string        `json:"id"`
	Name         string        `json:"name"`
	Description  string        `json:"description,omitempty"`
	Domains      []string      `json:"domains"`      // linked Beacon scan domains
	Integrations []Integration `json:"integrations"`
	Plans        []Plan        `json:"plans,omitempty"`
	CreatedAt    time.Time     `json:"created_at"`
	UpdatedAt    time.Time     `json:"updated_at"`
}

// ContextSummary is the unified view passed to the AI planner.
type ContextSummary struct {
	ProjectName       string     `json:"project_name"`
	Domains           []string   `json:"domains"`
	ExistingResources []Resource `json:"existing_resources"` // from all sources
	ManagedResources  []Resource `json:"managed_resources"`  // subset that's in Terraform
	UnmanagedGaps     []Resource `json:"unmanaged_gaps"`     // in cloud but not in Terraform
	Plans             []Plan     `json:"plans,omitempty"`
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Store is an in-memory project store.
type Store struct {
	mu       sync.RWMutex
	projects map[string]*Project
}

// NewStore creates an empty project store.
func NewStore() *Store {
	return &Store{projects: make(map[string]*Project)}
}

func (s *Store) Create(p *Project) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.ID == "" {
		p.ID = newID()
	}
	now := time.Now().UTC()
	p.CreatedAt = now
	p.UpdatedAt = now
	if p.Integrations == nil {
		p.Integrations = []Integration{}
	}
	if p.Domains == nil {
		p.Domains = []string{}
	}
	if p.Plans == nil {
		p.Plans = []Plan{}
	}
	s.projects[p.ID] = p
	return nil
}

func (s *Store) Get(id string) (*Project, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.projects[id]
	return p, ok
}

func (s *Store) List() []*Project {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Project, 0, len(s.projects))
	for _, p := range s.projects {
		out = append(out, p)
	}
	return out
}

func (s *Store) Update(p *Project) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.projects[p.ID]; !ok {
		return fmt.Errorf("project %q not found", p.ID)
	}
	p.UpdatedAt = time.Now().UTC()
	s.projects[p.ID] = p
	return nil
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.projects[id]; !ok {
		return fmt.Errorf("project %q not found", id)
	}
	delete(s.projects, id)
	return nil
}

// AddIntegration adds an integration to a project.
func (s *Store) AddIntegration(projectID string, intg Integration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.projects[projectID]
	if !ok {
		return fmt.Errorf("project %q not found", projectID)
	}
	if intg.ID == "" {
		intg.ID = newID()
	}
	if intg.Status == "" {
		intg.Status = "connected"
	}
	p.Integrations = append(p.Integrations, intg)
	p.UpdatedAt = time.Now().UTC()
	return nil
}

// RemoveIntegration removes an integration from a project by ID.
func (s *Store) RemoveIntegration(projectID, integrationID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.projects[projectID]
	if !ok {
		return fmt.Errorf("project %q not found", projectID)
	}
	for i, intg := range p.Integrations {
		if intg.ID == integrationID {
			p.Integrations = append(p.Integrations[:i], p.Integrations[i+1:]...)
			p.UpdatedAt = time.Now().UTC()
			return nil
		}
	}
	return fmt.Errorf("integration %q not found", integrationID)
}

// UpdateIntegration replaces an integration in a project.
func (s *Store) UpdateIntegration(projectID string, intg Integration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.projects[projectID]
	if !ok {
		return fmt.Errorf("project %q not found", projectID)
	}
	for i, existing := range p.Integrations {
		if existing.ID == intg.ID {
			p.Integrations[i] = intg
			p.UpdatedAt = time.Now().UTC()
			return nil
		}
	}
	return fmt.Errorf("integration %q not found", intg.ID)
}

// GetIntegration returns a specific integration from a project.
func (s *Store) GetIntegration(projectID, integrationID string) (*Integration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.projects[projectID]
	if !ok {
		return nil, fmt.Errorf("project %q not found", projectID)
	}
	for i := range p.Integrations {
		if p.Integrations[i].ID == integrationID {
			return &p.Integrations[i], nil
		}
	}
	return nil, fmt.Errorf("integration %q not found", integrationID)
}

// AddPlan adds a plan to a project.
func (s *Store) AddPlan(projectID string, plan Plan) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.projects[projectID]
	if !ok {
		return fmt.Errorf("project %q not found", projectID)
	}
	if plan.ID == "" {
		plan.ID = newID()
	}
	plan.CreatedAt = time.Now().UTC()
	p.Plans = append(p.Plans, plan)
	p.UpdatedAt = time.Now().UTC()
	return nil
}

// BuildContext produces the unified ContextSummary for AI planning.
func (s *Store) BuildContext(projectID string) (*ContextSummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.projects[projectID]
	if !ok {
		return nil, fmt.Errorf("project %q not found", projectID)
	}

	var allResources []Resource
	managedSet := make(map[string]bool) // "type:name" → managed

	for _, intg := range p.Integrations {
		for _, r := range intg.Resources {
			allResources = append(allResources, r)
			if r.Managed {
				managedSet[r.Type+":"+r.Name] = true
			}
		}
	}

	var managed, unmanaged []Resource
	seen := make(map[string]bool)
	for _, r := range allResources {
		key := r.Type + ":" + r.Name
		if r.Managed && !seen[key] {
			managed = append(managed, r)
			seen[key] = true
		} else if !managedSet[key] && r.Source != "terraform" {
			unmanaged = append(unmanaged, r)
		}
		// Resources that exist in cloud AND in Terraform are reconciled — skip unmanaged list.
	}

	return &ContextSummary{
		ProjectName:       p.Name,
		Domains:           p.Domains,
		ExistingResources: allResources,
		ManagedResources:  managed,
		UnmanagedGaps:     unmanaged,
		Plans:             p.Plans,
	}, nil
}
