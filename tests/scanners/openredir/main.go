package main

import (
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if u := r.URL.Query().Get("url"); u != "" {
			http.Redirect(w, r, u, http.StatusFound)
			return
		}
		if u := r.URL.Query().Get("redirect"); u != "" {
			http.Redirect(w, r, u, http.StatusFound)
			return
		}
		if u := r.URL.Query().Get("next"); u != "" {
			http.Redirect(w, r, u, http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	http.ListenAndServe(":8080", nil)
}
