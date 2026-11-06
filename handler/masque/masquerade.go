package masque

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

const (
	masqueradeTimeout = 10 * time.Second
	// masqueradeMaxBody caps the body relayed for a CONNECT; a website's answer
	// to one is an error page at most.
	masqueradeMaxBody = 1 << 20
)

// masquerade answers everything that is not an authenticated MASQUE request
// with the response of an upstream website, the way Hysteria's masquerade does.
// An active prober then sees the same site over HTTP/3 as over TCP, instead of
// a 405 or a 407 that gives the proxy away.
//
// Requests go upstream as they came in: method, path, query, body and the
// original Host, so name-based virtual hosting on the upstream picks the same
// site. Only the proxy credentials are dropped.
type masquerade struct {
	target *url.URL
	tls    *tls.Config
	proxy  *httputil.ReverseProxy
}

func newMasquerade(rawURL string, insecure bool) (*masquerade, error) {
	target, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("masquerade: %w", err)
	}
	if target.Scheme != "http" && target.Scheme != "https" || target.Hostname() == "" {
		return nil, fmt.Errorf("masquerade: want an http(s) URL, got %q", rawURL)
	}

	m := &masquerade{
		target: target,
		tls:    &tls.Config{ServerName: target.Hostname(), InsecureSkipVerify: insecure},
	}
	m.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
			stripProxyHeaders(pr.Out.Header)
		},
		Transport: &http.Transport{
			// Never route the masquerade through HTTP(S)_PROXY from the environment.
			Proxy: nil,
			// Pass Accept-Encoding through as the client sent it: letting the
			// transport ask for gzip itself changes the upstream's ETag.
			DisableCompression:    true,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          64,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   masqueradeTimeout,
			ResponseHeaderTimeout: 30 * time.Second,
			TLSClientConfig:       m.tls,
		},
		FlushInterval: -1,
		ErrorLog:      log.New(io.Discard, "", 0),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	return m, nil
}

func stripProxyHeaders(h http.Header) {
	h.Del("Proxy-Authorization")
	h.Del("Capsule-Protocol")
}

func (m *masquerade) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		m.serveConnect(w, r)
		return
	}
	m.proxy.ServeHTTP(w, r)
}

// serveConnect relays a CONNECT to the upstream over HTTP/1.1 and its answer
// back. net/http refuses to send CONNECT through a reverse proxy, but what the
// site says to one (Caddy: 404 for a path, an empty 200 for an unknown host) is
// what a prober expects to see.
func (m *masquerade) serveConnect(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), masqueradeTimeout)
	defer cancel()

	res, err := m.roundTripConnect(ctx, r)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer res.Body.Close()

	for k, vs := range res.Header {
		w.Header()[k] = vs
	}
	w.WriteHeader(res.StatusCode)
	io.Copy(w, io.LimitReader(res.Body, masqueradeMaxBody))
}

func (m *masquerade) roundTripConnect(ctx context.Context, r *http.Request) (*http.Response, error) {
	addr := m.target.Host
	if m.target.Port() == "" {
		port := "80"
		if m.target.Scheme == "https" {
			port = "443"
		}
		addr = net.JoinHostPort(m.target.Hostname(), port)
	}

	var conn net.Conn
	var err error
	if m.target.Scheme == "https" {
		d := &tls.Dialer{Config: m.tls.Clone()}
		d.Config.NextProtos = []string{"http/1.1"}
		conn, err = d.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })

	// A CONNECT-UDP request carries a path; a plain CONNECT only an authority.
	target := r.URL.RequestURI()
	if r.URL.Path == "" {
		target = r.Host
	}
	header := r.Header.Clone()
	stripProxyHeaders(header)

	bw := bufio.NewWriter(conn)
	fmt.Fprintf(bw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, r.Host)
	header.Write(bw)
	bw.WriteString("\r\n")
	if err := bw.Flush(); err != nil {
		stop()
		conn.Close()
		return nil, err
	}

	res, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		stop()
		conn.Close()
		return nil, err
	}
	res.Body = &connBody{ReadCloser: res.Body, conn: conn, stop: stop}
	return res, nil
}

// connBody closes the upstream connection with the response body.
type connBody struct {
	io.ReadCloser
	conn net.Conn
	stop func() bool
}

func (b *connBody) Close() error {
	b.stop()
	b.ReadCloser.Close()
	return b.conn.Close()
}

// masquerade serves r from the masquerade site, if one is configured, and
// reports whether it did.
func (h *masqueHandler) masquerade(w http.ResponseWriter, r *http.Request) bool {
	if h.masq == nil {
		return false
	}
	h.masq.ServeHTTP(w, r)
	return true
}
