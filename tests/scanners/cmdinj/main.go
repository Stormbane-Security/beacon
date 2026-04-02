// Deliberately vulnerable Go server with OS command injection in ?host= parameter.
package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

func main() {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<h1>Network Diagnostic Tool</h1>
			<form action="/api/v1/ping"><input name="host" placeholder="hostname"><button>Ping</button></form>`))
	})

	// VULNERABLE: user input passed directly to shell command
	http.HandleFunc("/api/v1/ping", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		if host == "" {
			host = "localhost"
		}
		// Deliberately vulnerable: unsanitized input in shell command
		cmd := exec.Command("sh", "-c", fmt.Sprintf("ping -c 1 %s 2>&1", host))
		out, err := cmd.CombinedOutput()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write(out)
	})

	// VULNERABLE: another endpoint with command injection
	http.HandleFunc("/tools/lookup", func(w http.ResponseWriter, r *http.Request) {
		domain := r.URL.Query().Get("domain")
		if domain == "" {
			domain = "localhost"
		}
		cmd := exec.Command("sh", "-c", fmt.Sprintf("nslookup %s 2>&1", domain))
		out, _ := cmd.CombinedOutput()
		w.Header().Set("Content-Type", "text/plain")
		w.Write(out)
	})

	fmt.Println("cmdinj-app listening on :8080")
	http.ListenAndServe(":8080", nil)
}
