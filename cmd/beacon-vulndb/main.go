// beacon-vulndb is a standalone vulnerability database service and CLI.
//
// Usage:
//
//	beacon-vulndb serve --port 8877 --db ./vulndb.sqlite
//	beacon-vulndb sync --source osv
//	beacon-vulndb status
//	beacon-vulndb query nginx 1.24.0
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/stormbane-security/beacon/internal/vulndb"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "serve":
		cmdServe(os.Args[2:])
	case "sync":
		cmdSync(os.Args[2:])
	case "status":
		cmdStatus(os.Args[2:])
	case "query":
		cmdQuery(os.Args[2:])
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `beacon-vulndb — vulnerability database service

Commands:
  serve   Start the HTTP API server
  sync    Ingest data from OSV or NVD
  status  Show database statistics
  query   Look up CVEs for a service/version

Options:
  --db PATH    SQLite database path (default: vulndb.sqlite)
  --port PORT  HTTP port for serve (default: 8877)
  --source SRC Sync source: osv (default: osv)`)
}

func parseFlags(args []string) map[string]string {
	flags := map[string]string{}
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "--") {
			key := strings.TrimPrefix(args[i], "--")
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				flags[key] = args[i+1]
				i++
			} else {
				flags[key] = "true"
			}
		} else {
			// Positional args stored by index.
			flags[fmt.Sprintf("_%d", i)] = args[i]
		}
	}
	return flags
}

func openDB(flags map[string]string) *vulndb.DB {
	path := flags["db"]
	if path == "" {
		path = "vulndb.sqlite"
	}
	db, err := vulndb.Open(path)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	return db
}

func cmdServe(args []string) {
	flags := parseFlags(args)
	port := 8877
	if p, ok := flags["port"]; ok {
		n, err := strconv.Atoi(p)
		if err != nil {
			log.Fatalf("invalid port: %s", p)
		}
		port = n
	}

	db := openDB(flags)
	defer db.Close()

	srv := vulndb.NewServer(db, port)
	log.Printf("beacon-vulndb serving on :%d", port)

	// Graceful shutdown on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down...")
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(shutCtx)
}

func cmdSync(args []string) {
	flags := parseFlags(args)
	source := flags["source"]
	if source == "" {
		source = "osv"
	}

	db := openDB(flags)
	defer db.Close()

	switch source {
	case "osv":
		log.Println("syncing from OSV...")
		n, err := vulndb.SyncOSV(db, nil)
		if err != nil {
			log.Fatalf("sync error: %v", err)
		}
		log.Printf("synced %d CVE entries from OSV", n)
	case "nvd":
		log.Println("NVD sync not yet implemented — use osv for now")
	default:
		log.Fatalf("unknown source: %s", source)
	}
}

func cmdStatus(args []string) {
	flags := parseFlags(args)
	db := openDB(flags)
	defer db.Close()

	stats, err := db.Stats()
	if err != nil {
		log.Fatalf("stats error: %v", err)
	}
	fmt.Printf("beacon-vulndb status\n")
	fmt.Printf("  CVE entries:     %d\n", stats.CVECount)
	fmt.Printf("  Payloads:        %d\n", stats.PayloadCount)
	fmt.Printf("  Fingerprints:    %d\n", stats.FingerprintCount)
	fmt.Printf("  Scan results:    %d\n", stats.ScanResultCount)
}

func cmdQuery(args []string) {
	flags := parseFlags(args)
	db := openDB(flags)
	defer db.Close()

	// Positional: query <service> [version]
	service := flags["_0"]
	version := flags["_1"]
	if service == "" {
		log.Fatal("usage: beacon-vulndb query <service> [version]")
	}

	cves, err := db.QueryCVEs(service, version)
	if err != nil {
		log.Fatalf("query error: %v", err)
	}
	if len(cves) == 0 {
		fmt.Printf("no CVEs found for %s", service)
		if version != "" {
			fmt.Printf(" %s", version)
		}
		fmt.Println()
		return
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(cves)
}
