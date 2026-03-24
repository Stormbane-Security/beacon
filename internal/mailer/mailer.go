// Package mailer defines the report delivery interface.
// Currently only stdout delivery is implemented. SMTP will be added later.
package mailer

import "github.com/stormbane/beacon/internal/store"

// Mailer delivers a completed report.
type Mailer interface {
	// Send delivers the report. For stdout, it prints to os.Stdout.
	// For SMTP (future), it sends an email.
	Send(report *store.Report) error
}
