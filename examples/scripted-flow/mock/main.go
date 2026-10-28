// This local API is a runnable example target, not a production service.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
)

func main() {
	address := flag.String("listen", "127.0.0.1:8099", "local listen address")
	flag.Parse()
	listener, err := net.Listen("tcp", *address)
	if err != nil {
		log.Fatal(err)
	}
	var mu sync.Mutex
	counter := 0
	amounts := map[string]int64{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/login" {
			mu.Lock()
			counter++
			sid := strconv.Itoa(counter)
			mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: sid, Path: "/"})
			fmt.Fprintf(w, `{"token":"demo-token-%s"}`, sid)
			return
		}
		cookie, err := r.Cookie("sid")
		if err != nil {
			http.Error(w, "missing session", 401)
			return
		}
		switch r.URL.Path {
		case "/create":
			if r.Header.Get("Authorization") != "Bearer demo-token-"+cookie.Value {
				http.Error(w, "wrong token", 401)
				return
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil {
				http.Error(w, "read body", 400)
				return
			}
			mac := hmac.New(sha256.New, []byte("local-demo-key"))
			mac.Write(body)
			signature, err := hex.DecodeString(r.Header.Get("X-Signature"))
			if err != nil || !hmac.Equal(signature, mac.Sum(nil)) {
				http.Error(w, "invalid signature", 401)
				return
			}
			var payload struct {
				Amount int64 `json:"amount"`
			}
			if json.Unmarshal(body, &payload) != nil {
				http.Error(w, "invalid amount", 400)
				return
			}
			mu.Lock()
			amounts[cookie.Value] = payload.Amount
			mu.Unlock()
			w.WriteHeader(201)
			fmt.Fprint(w, `{"id":9007199254740993}`)
		case "/read":
			if r.URL.Query().Get("id") != "9007199254740993" {
				http.Error(w, "wrong item id", 400)
				return
			}
			mu.Lock()
			amount, ok := amounts[cookie.Value]
			mu.Unlock()
			if !ok {
				http.Error(w, "missing item", 404)
				return
			}
			fmt.Fprintf(w, `{"amount":%d}`, amount)
		default:
			http.NotFound(w, r)
		}
	})
	fmt.Printf("Local demo API: http://%s\n", listener.Addr())
	log.Fatal(http.Serve(listener, handler))
}
