//go:build docker

package integration

import (
	"context"
	"os/exec"
)

// execCommandContext wraps exec.CommandContext for docker CLI calls.
func execCommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, name, args...)
}
