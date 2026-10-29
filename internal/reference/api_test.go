package reference_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	"github.com/kaitoz11/reqfuzzy/internal/reference"
)

func TestReferenceAPIEnforcesNonceSignatureAndAmountPolicy(t *testing.T) {
	for _, vulnerable := range []bool{false, true} {
		t.Run(fmt.Sprint(vulnerable), func(t *testing.T) {
			server := httptest.NewServer(reference.NewHandler(reference.Options{VulnerableAmounts: vulnerable}))
			defer server.Close()
			jar, _ := cookiejar.New(nil)
			client := &http.Client{Jar: jar}
			response, err := client.Post(server.URL+"/session", "application/json", bytes.NewBufferString(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			var session struct {
				Token string `json:"access_token"`
				Key   string `json:"signing_key"`
			}
			if err := json.NewDecoder(response.Body).Decode(&session); err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			req, _ := http.NewRequest("GET", server.URL+"/nonce", nil)
			req.Header.Set("Authorization", "Bearer "+session.Token)
			response, err = client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			var nonce struct {
				Value string `json:"nonce"`
			}
			json.NewDecoder(response.Body).Decode(&nonce)
			response.Body.Close()
			body := fmt.Sprintf(`{"amount":-10,"nonce":%q}`, nonce.Value)
			mac := hmac.New(sha256.New, []byte(session.Key))
			mac.Write([]byte(body))
			send := func(signature string) int {
				req, _ := http.NewRequest("POST", server.URL+"/transfer", bytes.NewBufferString(body))
				req.Header.Set("Authorization", "Bearer "+session.Token)
				req.Header.Set("X-Signature", signature)
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				return resp.StatusCode
			}
			if got := send("bad"); got != 401 {
				t.Fatalf("bad signature status=%d", got)
			}
			want := 422
			if vulnerable {
				want = 201
			}
			if got := send(hex.EncodeToString(mac.Sum(nil))); got != want {
				t.Fatalf("transfer status=%d want=%d", got, want)
			}
			if got := send(hex.EncodeToString(mac.Sum(nil))); got != 409 {
				t.Fatalf("replayed nonce accepted: %d", got)
			}
			req, _ = http.NewRequest("GET", server.URL+"/balance", nil)
			req.Header.Set("Authorization", "Bearer "+session.Token)
			response, err = client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			var balance struct {
				Value int `json:"balance"`
			}
			json.NewDecoder(response.Body).Decode(&balance)
			response.Body.Close()
			expected := 100
			if vulnerable {
				expected = 110
			}
			if balance.Value != expected {
				t.Fatalf("balance=%d want=%d", balance.Value, expected)
			}
		})
	}
}
