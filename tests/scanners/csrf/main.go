// Deliberately vulnerable Go server with POST forms missing CSRF protection.
package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	// Login form — no CSRF token, no SameSite cookie
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			http.SetCookie(w, &http.Cookie{
				Name:  "session",
				Value: "abc123",
				Path:  "/",
				// Deliberately missing SameSite attribute
			})
			w.Write([]byte("Logged in"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		// VULNERABLE: POST form with no hidden CSRF token field
		w.Write([]byte(`<!DOCTYPE html>
<html><body>
<h1>Login</h1>
<form method="POST" action="/login">
  <input type="text" name="username" placeholder="Username">
  <input type="password" name="password" placeholder="Password">
  <button type="submit">Login</button>
</form>
</body></html>`))
	})

	// Settings form — also no CSRF protection
	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<!DOCTYPE html>
<html><body>
<h1>Register</h1>
<form method="POST" action="/register">
  <input type="text" name="username">
  <input type="email" name="email">
  <input type="password" name="password">
  <button type="submit">Register</button>
</form>
</body></html>`))
	})

	// Safe page — GET form (should NOT trigger CSRF finding)
	http.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<!DOCTYPE html>
<html><body>
<form method="GET" action="/search">
  <input type="text" name="q">
  <button>Search</button>
</form>
</body></html>`))
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<h1>App</h1><a href="/login">Login</a> | <a href="/register">Register</a>`))
	})

	fmt.Println("csrf-app listening on :8080")
	http.ListenAndServe(":8080", nil)
}
