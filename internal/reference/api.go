// Package reference is a local acceptance API with an intentional, selectable amount bug.
// It is a test/demo target and must not be used as a production payment service.
package reference

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Options struct {
	VulnerableAmounts bool
	ExpireAtTransfer  bool
}
type account struct {
	Token, Key, Nonce string
	Balance           int64
	NonceUsed         bool
	Issued            time.Time
}

func NewHandler(options Options) http.Handler {
	var mutex sync.Mutex
	sequence := 0
	nonceSequence := 0
	accounts := map[string]*account{}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/session" {
			if r.Method != "POST" {
				http.Error(w, "method", 405)
				return
			}
			mutex.Lock()
			sequence++
			sid := strconv.Itoa(sequence)
			user := &account{Token: "reference-token-" + sid, Key: "reference-signing-" + sid, Balance: 100}
			accounts[sid] = user
			mutex.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "reference_sid", Value: sid, Path: "/", HttpOnly: true})
			fmt.Fprintf(w, `{"access_token":%q,"signing_key":%q,"balance":100}`, user.Token, user.Key)
			return
		}
		cookie, err := r.Cookie("reference_sid")
		if err != nil {
			http.Error(w, "session", 401)
			return
		}
		mutex.Lock()
		defer mutex.Unlock()
		user := accounts[cookie.Value]
		if user == nil || r.Header.Get("Authorization") != "Bearer "+user.Token {
			http.Error(w, "session", 401)
			return
		}
		switch r.URL.Path {
		case "/nonce":
			if r.Method != "GET" {
				http.Error(w, "method", 405)
				return
			}
			nonceSequence++
			user.Nonce = fmt.Sprintf("nonce-%s-%d", cookie.Value, nonceSequence)
			user.NonceUsed = false
			user.Issued = time.Now()
			fmt.Fprintf(w, `{"nonce":%q}`, user.Nonce)
		case "/balance":
			if r.Method != "GET" {
				http.Error(w, "method", 405)
				return
			}
			fmt.Fprintf(w, `{"balance":%d}`, user.Balance)
		case "/transfer":
			if r.Method != "POST" {
				http.Error(w, "method", 405)
				return
			}
			if options.ExpireAtTransfer {
				http.Error(w, "expired session", 401)
				return
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil {
				http.Error(w, "body", 400)
				return
			}
			mac := hmac.New(sha256.New, []byte(user.Key))
			_, _ = mac.Write(body)
			signature, err := hex.DecodeString(r.Header.Get("X-Signature"))
			if err != nil || !hmac.Equal(signature, mac.Sum(nil)) {
				http.Error(w, "signature", 401)
				return
			}
			var payload struct {
				Amount json.RawMessage `json:"amount"`
				Nonce  string          `json:"nonce"`
			}
			if err := json.Unmarshal(body, &payload); err != nil {
				http.Error(w, "JSON", 400)
				return
			}
			if payload.Nonce == "" || payload.Nonce != user.Nonce || user.NonceUsed || time.Since(user.Issued) > 10*time.Second {
				http.Error(w, "nonce", 409)
				return
			}
			user.NonceUsed = true
			text := strings.TrimSpace(string(payload.Amount))
			amount, err := strconv.ParseInt(text, 10, 64)
			if err != nil || amount < -1000 || amount > 1000 || amount > user.Balance || (!options.VulnerableAmounts && amount <= 0) {
				http.Error(w, "amount", 422)
				return
			}
			user.Balance -= amount
			w.WriteHeader(201)
			fmt.Fprint(w, `{"transaction_id":9007199254740993,"accepted":true}`)
		default:
			http.NotFound(w, r)
		}
	})
}
