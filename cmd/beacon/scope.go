package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/scope"
)

// cmdScope queries bug bounty program scope from HackerOne, Bugcrowd, or Intigriti.
//
// Usage:
//
//	beacon scope hackerone:<handle>    Show in-scope assets for a HackerOne program
//	beacon scope bugcrowd:<handle>    Show in-scope assets for a Bugcrowd program
//	beacon scope intigriti:<handle>   Show in-scope assets for an Intigriti program
//	beacon scope hackerone:uber       Example: Uber on HackerOne
func cmdScope(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, `Usage:
  beacon scope <platform>:<handle>    Query program scope

Examples:
  beacon scope hackerone:uber
  beacon scope bugcrowd:twitch
  beacon scope intigriti:example
  beacon scope h1:github
  beacon scope ig:example`)
		os.Exit(1)
	}

	parts := strings.SplitN(args[0], ":", 2)
	if len(parts) != 2 {
		fatalf("invalid format: use <platform>:<handle> (e.g., hackerone:uber)")
	}
	platform, handle := parts[0], parts[1]

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Fprintf(os.Stderr, "beacon: fetching scope for %s/%s...\n", platform, handle)

	program, err := scope.FetchProgram(ctx, platform, handle)
	if err != nil {
		fatalf("scope: %v", err)
	}

	inScope := program.InScopeAssets()
	outOfScope := program.OutOfScopeAssets()

	if program.Name != "" {
		fmt.Printf("Program: %s\n", program.Name)
	}
	fmt.Printf("Platform: %s\n", program.Platform)
	fmt.Printf("Handle: %s\n\n", program.Handle)

	fmt.Printf("IN SCOPE (%d assets):\n", len(inScope))
	for _, a := range inScope {
		severity := ""
		if a.MaxSeverity != "" {
			severity = fmt.Sprintf(" (max: %s)", a.MaxSeverity)
		}
		fmt.Printf("  %-40s %s%s\n", a.Identifier, a.Type, severity)
	}

	if len(outOfScope) > 0 {
		fmt.Printf("\nOUT OF SCOPE (%d assets):\n", len(outOfScope))
		for _, a := range outOfScope {
			fmt.Printf("  %-40s %s\n", a.Identifier, a.Type)
		}
	}

	// Print scan command suggestion
	if len(inScope) > 0 {
		fmt.Printf("\nTo scan all in-scope assets:\n")
		var domains []string
		for _, a := range inScope {
			if a.Type == "URL" || a.Type == "WILDCARD" || a.Type == "" {
				domains = append(domains, a.Identifier)
			}
		}
		if len(domains) > 3 {
			domains = domains[:3]
		}
		if len(domains) > 0 {
			fmt.Printf("  beacon scan --domain %s\n", strings.Join(domains, " --host "))
		}
	}
}
