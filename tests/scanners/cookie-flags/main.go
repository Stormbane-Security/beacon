package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// VULNERABLE: session cookie set without Secure, HttpOnly, or SameSite flags
		w.Header().Add("Set-Cookie", "session_id=abc123def456; Path=/")
		w.Header().Add("Set-Cookie", "user_prefs=dark_mode; Path=/")
		w.WriteHeader(200)
		fmt.Fprint(w, "<html><body><h1>Cookie Test</h1></body></html>")
	})
	http.ListenAndServe(":8080", nil)
}
