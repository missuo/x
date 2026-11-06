package masque

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/handler"
	xlogger "github.com/go-gost/x/logger"
)

type staticAuther struct{ user, pass string }

func (a staticAuther) Authenticate(_ context.Context, user, pass string, _ ...auth.Option) (string, bool) {
	return user, user == a.user && pass == a.pass
}

func newSite(t *testing.T) *httptest.Server {
	t.Helper()
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Caddy")
		w.Header().Set("X-Seen-Host", r.Host)
		w.Header().Set("X-Seen-Auth", r.Header.Get("Proxy-Authorization"))
		w.Header().Set("X-Seen-Method", r.Method)
		io.WriteString(w, "<title>Tokens</title>"+r.URL.RequestURI())
	}))
	t.Cleanup(site.Close)
	return site
}

func TestMasqueradeProxiesRequestAsIs(t *testing.T) {
	site := newSite(t)
	masq, err := newMasquerade(site.URL, false)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://beta.tokens.ci/robots.txt?x=1", nil)
	req.Header.Set("Proxy-Authorization", "Basic dTpw")
	rec := httptest.NewRecorder()
	masq.ServeHTTP(rec, req)

	res := rec.Result()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK || string(body) != "<title>Tokens</title>/robots.txt?x=1" {
		t.Fatalf("got %d %q", res.StatusCode, body)
	}
	if got := res.Header.Get("Server"); got != "Caddy" {
		t.Errorf("Server header %q, want the upstream's", got)
	}
	if got := res.Header.Get("X-Seen-Host"); got != "beta.tokens.ci" {
		t.Errorf("upstream saw Host %q, want the original", got)
	}
	if got := res.Header.Get("X-Seen-Auth"); got != "" {
		t.Errorf("proxy credentials leaked upstream: %q", got)
	}
}

func TestMasqueradeRejectsBadURL(t *testing.T) {
	for _, u := range []string{"", "ftp://example.com", "example.com", "http://"} {
		if _, err := newMasquerade(u, false); err == nil {
			t.Errorf("%q: want error", u)
		}
	}
}

func TestFailedAuthMasqueradesInsteadOf407(t *testing.T) {
	site := newSite(t)
	h := NewHandler(handler.AutherOption(staticAuther{"u", "p"})).(*masqueHandler)
	masq, err := newMasquerade(site.URL, false)
	if err != nil {
		t.Fatal(err)
	}
	h.masq = masq

	// An extended CONNECT as quic-go's http3 server hands it over.
	req := httptest.NewRequest(http.MethodGet, "https://beta.tokens.ci/.well-known/masque/udp/1.1.1.1/53/", nil)
	req.Method = http.MethodConnect
	req.Proto = "connect-udp"
	req.Header.Set("Proxy-Authorization", "Basic dTp3cm9uZw==") // u:wrong
	rec := httptest.NewRecorder()
	if _, ok := h.authenticate(context.Background(), rec, req, xlogger.Nop()); ok {
		t.Fatal("wrong password authenticated")
	}
	res := rec.Result()
	if res.StatusCode == http.StatusProxyAuthRequired || res.Header.Get("Proxy-Authenticate") != "" {
		t.Fatalf("got a proxy challenge: %d %v", res.StatusCode, res.Header)
	}
	if got := res.Header.Get("X-Seen-Method"); got != http.MethodConnect || res.Header.Get("Server") != "Caddy" {
		t.Fatalf("got %d %v, want the masquerade site's answer to the CONNECT", res.StatusCode, res.Header)
	}
	if got := res.Header.Get("X-Seen-Host"); got != "beta.tokens.ci" {
		t.Errorf("upstream saw Host %q", got)
	}
	if got := res.Header.Get("X-Seen-Auth"); got != "" {
		t.Errorf("proxy credentials leaked upstream: %q", got)
	}

	// Without a masquerade site the old 407 challenge stays.
	h.masq = nil
	rec = httptest.NewRecorder()
	h.authenticate(context.Background(), rec, req, xlogger.Nop())
	if rec.Code != http.StatusProxyAuthRequired {
		t.Fatalf("got %d, want 407 without masquerade", rec.Code)
	}

	// The right password still gets through.
	h.masq = masq
	req.Header.Set("Proxy-Authorization", "Basic dTpw") // u:p
	if _, ok := h.authenticate(context.Background(), httptest.NewRecorder(), req, xlogger.Nop()); !ok {
		t.Fatal("right password rejected")
	}
}
