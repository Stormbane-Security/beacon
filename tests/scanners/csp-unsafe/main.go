package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// VULNERABLE: CSP with unsafe-inline and unsafe-eval, plus wildcard source
		w.Header().Set("Content-Security-Policy", "default-src *; script-src 'unsafe-inline' 'unsafe-eval' *; style-src 'unsafe-inline' *")
		w.WriteHeader(200)
		fmt.Fprint(w, "<html><body><h1>CSP Test</h1><script>document.write('inline script')</script></body></html>")
	})
	http.ListenAndServe(":8080", nil)
}
