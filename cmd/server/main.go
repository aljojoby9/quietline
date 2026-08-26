package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aljojoby9/quietline/internal/server"
)

func main() {
	log.SetFlags(log.LstdFlags)
	dsn := getenv("QUIETLINE_DSN", "sqlite:quietline.db")
	addr := getenv("QUIETLINE_LISTEN", ":8080")
	store, err := server.OpenStore(dsn)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer store.Close()
	s := server.New(store)
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("quietline relay listening on %s (%s)", addr, redactDSN(dsn))
	log.Fatal(srv.ListenAndServe())
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func redactDSN(dsn string) string {
	// postgres://user:pass@host/db -> postgres://user:@host/db
	if i := strings.Index(dsn, "://"); i >= 0 {
		rest := dsn[i+3:]
		if at := strings.Index(rest, "@"); at >= 0 {
			userpass := rest[:at]
			if c := strings.Index(userpass, ":"); c >= 0 {
				return dsn[:i+3] + userpass[:c] + ":***" + rest[at:]
			}
		}
	}
	return dsn
}
