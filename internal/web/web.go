package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed static/*
var dist embed.FS

func Setup() http.Handler {
	mux := http.NewServeMux()

	staticFS, err := fs.Sub(dist, "static")
	if err != nil {
		panic(err)
	}

	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	mux.Handle("/", serveSPA(staticFS))

	return mux
}

func serveSPA(staticFS fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(staticFS))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := staticFS.Open(strings.TrimLeft(r.URL.Path, "/")); err != nil {
			r.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, r)
	})
}
