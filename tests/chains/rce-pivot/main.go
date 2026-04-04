// Vulnerable web server with command injection in /ping endpoint.
// Used by drydock chain test: rce-pivot-internal.
package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

func main() {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	// Intentionally vulnerable: passes user input directly to shell.
	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		if host == "" {
			http.Error(w, "missing host param", 400)
			return
		}
		// VULNERABLE: shell injection via unsanitized input
		out, _ := exec.Command("sh", "-c", "ping -c 1 -W 1 "+host).CombinedOutput()
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, string(out))
	})

	http.ListenAndServe(":8080", nil)
}
