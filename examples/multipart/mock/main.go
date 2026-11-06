package main

import (
	"flag"
	"github.com/kaitoz11/reqfuzzy/internal/uploadref"
	"log"
	"net/http"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8099", "local listen address")
	vulnerable := flag.Bool("vulnerable", false, "accept unsafe filenames in the in-memory fixture")
	flag.Parse()
	log.Fatal(http.ListenAndServe(*listen, uploadref.New(*vulnerable)))
}
