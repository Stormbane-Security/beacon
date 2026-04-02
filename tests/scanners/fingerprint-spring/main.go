// Go server mimicking Spring Boot actuator exposure patterns.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	// Mimic Spring Boot root
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Application-Context", "application:prod:8080")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<!DOCTYPE html><html><head><title>Spring App</title></head>
		<body><h1>Welcome</h1></body></html>`))
	})

	// Spring Boot Actuator endpoints (deliberately exposed)
	http.HandleFunc("/actuator", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"_links": map[string]any{
				"self":   map[string]string{"href": "/actuator"},
				"health": map[string]string{"href": "/actuator/health"},
				"env":    map[string]string{"href": "/actuator/env"},
				"beans":  map[string]string{"href": "/actuator/beans"},
			},
		})
	})

	http.HandleFunc("/actuator/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status": "UP",
			"components": map[string]any{
				"db":   map[string]string{"status": "UP"},
				"disk": map[string]string{"status": "UP"},
			},
		})
	})

	http.HandleFunc("/actuator/env", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"activeProfiles": []string{"prod"},
			"propertySources": []map[string]any{
				{"name": "systemEnvironment", "properties": map[string]any{
					"JAVA_HOME": map[string]string{"value": "/usr/lib/jvm/java-17"},
				}},
			},
		})
	})

	// Error page with Spring Boot signature
	http.HandleFunc("/error", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(map[string]any{
			"timestamp": "2024-01-15T10:30:00.000+00:00",
			"status":    404,
			"error":     "Not Found",
			"path":      r.URL.Path,
		})
	})

	fmt.Println("spring-app listening on :8080")
	http.ListenAndServe(":8080", nil)
}
