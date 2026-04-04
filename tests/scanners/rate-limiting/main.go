package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		// VULNERABLE: no rate limiting — allows brute force attacks
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, `{"status":"ok","message":"login endpoint"}`)
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, `{"status":"ok"}`)
	})
	_ = http.ListenAndServe(":8080", nil)
}
