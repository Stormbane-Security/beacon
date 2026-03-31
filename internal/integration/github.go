// Package integration provides external system connectors for projects:
// GitHub repo discovery, cloud account linking, and Terraform parsing.
package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane/beacon/internal/project"
)

// GitHubClient discovers repos, Terraform files, and state from GitHub.
type GitHubClient struct {
	token  string
	client *http.Client
}

// NewGitHubClient creates a client with the given personal access token.
func NewGitHubClient(token string) *GitHubClient {
	return &GitHubClient{
		token:  token,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (g *GitHubClient) do(ctx context.Context, method, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10 MiB cap
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API HTTP %d: %s", resp.StatusCode, string(data[:min(len(data), 500)]))
	}
	return data, nil
}

// Repo is a minimal GitHub repository.
type Repo struct {
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
	Private       bool   `json:"private"`
	Description   string `json:"description"`
}

// ListRepos returns repos accessible to the token. For orgs, use ListOrgRepos.
func (g *GitHubClient) ListRepos(ctx context.Context) ([]Repo, error) {
	data, err := g.do(ctx, http.MethodGet, "https://api.github.com/user/repos?per_page=100&sort=updated")
	if err != nil {
		return nil, err
	}
	var repos []Repo
	if err := json.Unmarshal(data, &repos); err != nil {
		return nil, fmt.Errorf("parsing repos: %w", err)
	}
	return repos, nil
}

// ListOrgRepos returns repos for a specific org.
func (g *GitHubClient) ListOrgRepos(ctx context.Context, org string) ([]Repo, error) {
	data, err := g.do(ctx, http.MethodGet, fmt.Sprintf("https://api.github.com/orgs/%s/repos?per_page=100&sort=updated", org))
	if err != nil {
		return nil, err
	}
	var repos []Repo
	if err := json.Unmarshal(data, &repos); err != nil {
		return nil, fmt.Errorf("parsing repos: %w", err)
	}
	return repos, nil
}

// TreeEntry is a file in a Git tree.
type TreeEntry struct {
	Path string `json:"path"`
	Type string `json:"type"` // "blob" or "tree"
	Size int    `json:"size"`
}

// DiscoverTerraformFiles finds all .tf and .tfstate files in a repo.
func (g *GitHubClient) DiscoverTerraformFiles(ctx context.Context, owner, repo, branch string) ([]TreeEntry, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/git/trees/%s?recursive=1", owner, repo, branch)
	data, err := g.do(ctx, http.MethodGet, url)
	if err != nil {
		return nil, err
	}
	var tree struct {
		Tree      []TreeEntry `json:"tree"`
		Truncated bool        `json:"truncated"`
	}
	if err := json.Unmarshal(data, &tree); err != nil {
		return nil, fmt.Errorf("parsing tree: %w", err)
	}

	var tfFiles []TreeEntry
	for _, e := range tree.Tree {
		if e.Type != "blob" {
			continue
		}
		if strings.HasSuffix(e.Path, ".tf") || strings.HasSuffix(e.Path, ".tf.json") ||
			strings.HasSuffix(e.Path, ".tfstate") || e.Path == "terraform.tfstate" {
			tfFiles = append(tfFiles, e)
		}
	}
	return tfFiles, nil
}

// GetFileContent reads a file from a repo.
func (g *GitHubClient) GetFileContent(ctx context.Context, owner, repo, path string) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s", owner, repo, path)
	data, err := g.do(ctx, http.MethodGet, url)
	if err != nil {
		return "", err
	}
	var file struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return "", fmt.Errorf("parsing file: %w", err)
	}
	if file.Encoding == "base64" {
		decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(file.Content, "\n", ""))
		if err != nil {
			return "", fmt.Errorf("decoding base64: %w", err)
		}
		return string(decoded), nil
	}
	return file.Content, nil
}

// SyncRepoResources discovers Terraform resources in a repo and returns them.
func (g *GitHubClient) SyncRepoResources(ctx context.Context, owner, repo, branch string) ([]project.Resource, error) {
	files, err := g.DiscoverTerraformFiles(ctx, owner, repo, branch)
	if err != nil {
		return nil, err
	}

	var resources []project.Resource
	for _, f := range files {
		if strings.HasSuffix(f.Path, ".tfstate") {
			// Parse state file for actual deployed resources.
			content, err := g.GetFileContent(ctx, owner, repo, f.Path)
			if err != nil {
				continue // skip unreadable files
			}
			stateResources := ParseTFState(content)
			for i := range stateResources {
				stateResources[i].FilePath = f.Path
			}
			resources = append(resources, stateResources...)
			continue
		}

		if strings.HasSuffix(f.Path, ".tf") {
			content, err := g.GetFileContent(ctx, owner, repo, f.Path)
			if err != nil {
				continue
			}
			hclResources := ParseHCL(content)
			for i := range hclResources {
				hclResources[i].FilePath = f.Path
			}
			resources = append(resources, hclResources...)
		}
	}
	return resources, nil
}
