// Package web serves the Beacon web UI from embedded static files.
// The UI is a self-contained single-page application that communicates
// with the beacond REST API at /v1/.
package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static
var staticFiles embed.FS

// Handler returns an HTTP handler that serves the Beacon web UI from
// the embedded static/ directory. Mount this at /ui/ in the mux.
func Handler() http.Handler {
	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic("web: failed to sub static FS: " + err.Error())
	}
	return http.FileServer(http.FS(sub))
}
