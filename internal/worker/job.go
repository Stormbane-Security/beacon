// Package worker manages the scan job queue and execution pool.
// The in-memory implementation is used for single-node deployments.
// The Queue interface is designed so a Redis backend can be swapped in later.
package worker

import (
	"time"

	"github.com/stormbane/beacon/internal/module"
	"github.com/stormbane/beacon/internal/store"
)

// Job is a unit of scan work submitted to the queue.
type Job struct {
	ScanRunID           string
	Domain              string
	ScanType            module.ScanType
	PermissionConfirmed bool
	SubmittedAt         time.Time
}

// JobStatus is the live status of a running or completed job.
type JobStatus struct {
	ScanRunID string
	Status    store.ScanStatus
	Progress  []string // log lines emitted so far
	Error     string
}
