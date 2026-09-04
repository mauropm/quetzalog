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
	mux.Handle("/", serveSPA(dist))

	return mux
}

func serveSPA(dist embed.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if !strings.HasPrefix(path, "/static/") {
			r.URL.Path = "/"
			fileServer := http.FileServer(http.FS(dist))
			fileServer.ServeHTTP(w, r)
			return
		}
		fileServer := http.FileServer(http.FS(dist))
		fileServer.ServeHTTP(w, r)
	})
}
