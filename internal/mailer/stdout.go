package mailer

import (
	"fmt"
	"os"
	"strings"

	"github.com/stormbane/beacon/internal/store"
)

// StdoutMailer prints the report HTML to stdout.
// Used as the default delivery method until SMTP is wired up.
type StdoutMailer struct{}

func NewStdout() *StdoutMailer { return &StdoutMailer{} }

func (m *StdoutMailer) Send(report *store.Report) error {
	sep := strings.Repeat("─", 72)
	fmt.Fprintf(os.Stdout, "\n%s\n", sep)
	fmt.Fprintf(os.Stdout, "  Beacon Security Report — %s\n", report.Domain)
	fmt.Fprintf(os.Stdout, "%s\n\n", sep)
	fmt.Fprint(os.Stdout, report.HTMLContent)
	fmt.Fprintf(os.Stdout, "\n%s\n", sep)
	return nil
}
