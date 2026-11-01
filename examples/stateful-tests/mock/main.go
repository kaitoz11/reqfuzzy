package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/kaitoz11/reqfuzzy/internal/reference"
)

func main() {
	address := flag.String("listen", "127.0.0.1:8098", "local listen address")
	vulnerable := flag.Bool("vulnerable-amounts", false, "enable the intentional negative-amount bug")
	expired := flag.Bool("expire-at-transfer", false, "simulate an invalid session at the tested step")
	refresh := flag.Bool("refresh-once", false, "expire the first transfer and enable cookie-authenticated refresh")
	flag.Parse()
	listener, err := net.Listen("tcp", *address)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Reference API: http://%s (vulnerable amounts: %t; expired transfer session: %t; refresh recovery: %t)\n", listener.Addr(), *vulnerable, *expired, *refresh)
	log.Fatal(http.Serve(listener, reference.NewHandler(reference.Options{VulnerableAmounts: *vulnerable, ExpireAtTransfer: *expired, RefreshOnce: *refresh})))
}
