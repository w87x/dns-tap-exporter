// Package ui serves the built-in single-page dashboard and its JSON API.
package ui

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"time"

	"github.com/w87x/dns-tap-exporter/internal/collector"
	"github.com/w87x/dns-tap-exporter/internal/history"
)

//go:embed web
var assets embed.FS

// Register mounts /ui/, /api/history and /api/now on mux.
func Register(mux *http.ServeMux, rec *history.Recorder, now func() collector.View, keep time.Duration) {
	sub, _ := fs.Sub(assets, "web")
	mux.Handle("/ui/", http.StripPrefix("/ui/", noStore(http.FileServer(http.FS(sub)))))
	mux.HandleFunc("/ui", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/", http.StatusFound)
	})

	mux.HandleFunc("/api/history", func(w http.ResponseWriter, r *http.Request) {
		rng := 6 * time.Hour
		if s := r.URL.Query().Get("range"); s != "" {
			d, err := time.ParseDuration(s)
			if err != nil || d <= 0 {
				http.Error(w, "bad range", http.StatusBadRequest)
				return
			}
			rng = d
		}
		rng = min(rng, keep)
		pts := rec.Since(time.Now().Add(-rng))
		if pts == nil {
			pts = []collector.View{}
		}
		writeJSON(w, map[string]any{"interval_sec": rec.Interval.Seconds(), "points": pts})
	})
	mux.HandleFunc("/api/now", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, now()) })
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func noStore(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src data:")
		h.ServeHTTP(w, r)
	})
}
