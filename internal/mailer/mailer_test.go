package mailer

import (
	"testing"

	"github.com/stormbane-security/beacon/internal/store"
)

func TestStdoutMailer_Send(t *testing.T) {
	m := NewStdout()
	report := &store.Report{
		Domain:      "example.com",
		HTMLContent: "<h1>Test Report</h1>",
	}
	if err := m.Send(report); err != nil {
		t.Errorf("Send() error = %v", err)
	}
}

func TestStdoutMailer_ImplementsInterface(t *testing.T) {
	var _ Mailer = NewStdout()
}
