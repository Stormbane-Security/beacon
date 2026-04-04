package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

// Deliberately vulnerable file server with path traversal.
// Serves files from /app/public but does NOT sanitize "../" in the path.
func main() {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "OK")
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_, _ = fmt.Fprint(w, "<html><body><h1>File Viewer</h1><a href='/files?name=readme.txt'>View readme</a></body></html>")
			return
		}
		http.NotFound(w, r)
	})

	http.HandleFunc("/files", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "name parameter required", 400)
			return
		}
		// VULNERABLE: no sanitization of "../" sequences
		path := filepath.Join("/app/public", name)
		data, err := os.ReadFile(path)
		if err != nil {
			http.Error(w, "File not found", 404)
			return
		}
		_, _ = w.Write(data)
	})

	fmt.Println("Path traversal vulnerable server listening on :8080")
	_ = http.ListenAndServe(":8080", nil)
}
