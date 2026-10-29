package attacker_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/imroc/req/v3"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
)

func TestCookieEditsPreserveCommonCookieHeaders(t *testing.T) {
	for _, header := range []string{"Cookie", "cookie"} {
		for _, remove := range []bool{false, true} {
			seen := make(chan []*http.Cookie, 2)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen <- r.Cookies(); w.WriteHeader(204) }))
			t.Cleanup(server.Close)
			client := attacker.NewHClient()
			t.Cleanup(client.CloseIdleConnections)
			client.UseBaseURL(server.URL)
			client.WithUpdatedClient(func(c *req.Client) { c.SetCommonHeaderNonCanonical(header, "sid=common; keep=yes") })
			request, err := client.ParseRawRequest([]byte("GET / HTTP/1.1\r\n\r\n"))
			if err != nil {
				t.Fatal(err)
			}
			values, err := request.CookieValues("sid")
			if err != nil || len(values) != 1 || values[0] != "common" {
				t.Fatalf("effective common cookies=%q err=%v", values, err)
			}
			if remove {
				err = request.RemoveCookieValue("sid")
			} else {
				err = request.SetCookieValue("sid", "changed")
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.SendRequest(request); err != nil {
				t.Fatal(err)
			}
			got := <-seen
			sid, keep := 0, 0
			for _, cookie := range got {
				if cookie.Name == "sid" {
					sid++
					if cookie.Value != "changed" {
						t.Fatalf("old common cookie reinserted")
					}
				}
				if cookie.Name == "keep" && cookie.Value == "yes" {
					keep++
				}
			}
			if keep != 1 || (remove && sid != 0) || (!remove && sid != 1) {
				t.Fatalf("cookie counts sid=%d keep=%d", sid, keep)
			}
			fresh, err := client.ParseRawRequest([]byte("GET / HTTP/1.1\r\n\r\n"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.SendRequest(fresh); err != nil {
				t.Fatal(err)
			}
			got = <-seen
			if len(got) != 2 || got[0].Value != "common" || got[1].Value != "yes" {
				t.Fatalf("common headers were changed globally")
			}
			client.CloseIdleConnections()
			server.Close()
		}
	}
}

func dumpWorkers() int {
	buffer := make([]byte, 1<<20)
	n := runtime.Stack(buffer, true)
	return strings.Count(string(buffer[:n]), "internal/dump.(*Dumper).Start")
}

func TestCookieEditsDoNotLeakClonedDumpWorkers(t *testing.T) {
	before := dumpWorkers()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer server.Close()
	client := attacker.NewHClient()
	client.UseBaseURL(server.URL)
	defer client.CloseIdleConnections()
	client.WithUpdatedClient(func(c *req.Client) { c.EnableDumpAllTo(io.Discard); t.Cleanup(c.Dump.Stop) })
	for i := 0; i < 3; i++ {
		request, err := client.ParseRawRequest([]byte("GET / HTTP/1.1\r\n\r\n"))
		if err != nil {
			t.Fatal(err)
		}
		if err := request.SetCookieValue("sid", "changed"); err != nil {
			t.Fatal(err)
		}
		if _, err := client.SendRequest(request); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if dumpWorkers() <= before+1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("edited requests leaked dump workers: before=%d after=%d", before, dumpWorkers())
}
