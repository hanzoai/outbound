// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package outbound

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http/httpproxy"
)

// ── Public ──────────────────────────────────────────────────────────────────
//
// Each case names what it is, because "192.0.0.170 must be false" is unreviewable
// and a wrong row here is a hole nobody would spot. The rows marked ADMITTED were
// admitted by the guard crawl carried before this package: IsGlobalUnicast &&
// !IsPrivate, plus 0/8 and CGNAT.

var publicCases = []struct {
	addr string
	want bool
	what string
}{
	// IPv4 special-purpose registry.
	{"0.0.0.0", false, "unspecified"},
	{"0.1.2.3", false, "0/8 this network"},
	{"10.0.0.1", false, "RFC 1918 10/8"},
	{"10.255.255.255", false, "top of 10/8"},
	{"100.64.0.1", false, "CGNAT"},
	{"100.100.100.200", false, "Alibaba metadata, in CGNAT"},
	{"100.127.255.255", false, "top of CGNAT"},
	{"127.0.0.1", false, "loopback"},
	{"127.1.2.3", false, "the rest of 127/8"},
	{"169.254.169.254", false, "the metadata endpoint"},
	{"169.254.0.1", false, "link-local"},
	{"172.16.0.1", false, "RFC 1918 172.16/12"},
	{"172.31.255.255", false, "top of 172.16/12"},
	{"192.0.0.1", false, "IETF protocol assignments — ADMITTED"},
	{"192.0.0.170", false, "NAT64 discovery — ADMITTED"},
	{"192.0.0.192", false, "Oracle metadata — ADMITTED"},
	{"192.0.2.1", false, "TEST-NET-1 — ADMITTED"},
	{"192.31.196.1", false, "AS112-v4 — ADMITTED"},
	{"192.52.193.1", false, "AMT — ADMITTED"},
	{"192.88.99.1", false, "6to4 relay anycast — ADMITTED"},
	{"192.168.1.1", false, "RFC 1918 192.168/16"},
	{"192.175.48.1", false, "direct delegation AS112 — ADMITTED"},
	{"198.18.0.1", false, "benchmarking — ADMITTED"},
	{"198.19.255.255", false, "top of benchmarking — ADMITTED"},
	{"198.51.100.1", false, "TEST-NET-2 — ADMITTED"},
	{"203.0.113.1", false, "TEST-NET-3 — ADMITTED"},
	{"224.0.0.1", false, "multicast"},
	{"239.255.255.250", false, "SSDP multicast"},
	{"240.0.0.1", false, "reserved 240/4 — ADMITTED"},
	{"255.255.255.255", false, "limited broadcast"},

	// IPv4 that must stay reachable, including both sides of each boundary.
	{"1.1.1.1", true, "public"},
	{"8.8.8.8", true, "public"},
	{"93.184.216.34", true, "public"},
	{"172.15.255.255", true, "just below 172.16/12"},
	{"172.32.0.0", true, "just above 172.16/12"},
	{"100.63.255.255", true, "just below CGNAT"},
	{"100.128.0.0", true, "just above CGNAT"},
	{"198.17.255.255", true, "just below benchmarking"},
	{"198.20.0.0", true, "just above benchmarking"},
	{"223.255.255.255", true, "just below multicast"},

	// IPv4-mapped IPv6 is the IPv4 it maps.
	{"::ffff:127.0.0.1", false, "mapped loopback"},
	{"::ffff:169.254.169.254", false, "mapped metadata"},
	{"::ffff:10.0.0.1", false, "mapped RFC 1918"},
	{"::ffff:8.8.8.8", true, "mapped public"},

	// IPv6 embedding an IPv4 address.
	{"64:ff9b::a9fe:a9fe", false, "NAT64 of 169.254.169.254 — ADMITTED"},
	{"64:ff9b::7f00:1", false, "NAT64 of 127.0.0.1 — ADMITTED"},
	{"64:ff9b::a00:1", false, "NAT64 of 10.0.0.1 — ADMITTED"},
	{"64:ff9b::c0a8:101", false, "NAT64 of 192.168.1.1 — ADMITTED"},
	{"64:ff9b::808:808", false, "NAT64, refused whatever it carries — ADMITTED"},
	{"64:ff9b:1::a00:1", false, "local-use NAT64 — ADMITTED"},
	{"64:ff9b:1::808:808", false, "local-use NAT64, even carrying a public address — ADMITTED"},
	{"2002:a9fe:a9fe::1", false, "6to4 of 169.254.169.254 — ADMITTED"},
	{"2002:c0a8:101::1", false, "6to4 of 192.168.1.1 — ADMITTED"},
	{"2002:808:808::1", false, "6to4, deprecated whatever it carries — ADMITTED"},
	{"2001:0:4136:e378:8000:63bf:3fff:fdd2", false, "Teredo — ADMITTED"},
	{"::127.0.0.1", false, "IPv4-compatible loopback — ADMITTED"},
	{"::8.8.8.8", false, "IPv4-compatible, deprecated whatever it carries — ADMITTED"},

	// IPv6 special-purpose registry.
	{"::", false, "unspecified"},
	{"::1", false, "loopback"},
	{"100::1", false, "discard-only — ADMITTED"},
	{"2001:1::1", false, "PCP anycast — ADMITTED"},
	{"2001:2::1", false, "benchmarking — ADMITTED"},
	{"2001:3::1", false, "AMT — ADMITTED"},
	{"2001:4:112::1", false, "AS112-v6 — ADMITTED"},
	{"2001:10::1", false, "deprecated ORCHID — ADMITTED"},
	{"2001:20::1", false, "ORCHIDv2 — ADMITTED"},
	{"2001:1ff:ffff::1", false, "top of IETF protocol assignments — ADMITTED"},
	{"2001:db8::1", false, "documentation — ADMITTED"},
	{"2620:4f:8000::1", false, "direct delegation AS112 — ADMITTED"},
	{"3fff::1", false, "documentation (RFC 9637) — ADMITTED"},
	{"5f00::1", false, "SRv6 SIDs — ADMITTED"},
	{"fc00::1", false, "unique-local"},
	{"fd00:ec2::254", false, "AWS metadata over IPv6, unique-local"},
	{"fe80::1", false, "link-local"},
	{"fe80::1%eth0", false, "zoned link-local"},
	{"fec0::1", false, "deprecated site-local — ADMITTED"},
	{"ff02::1", false, "multicast"},
	{"ff05::1:3", false, "site multicast"},

	// IPv6 that must stay reachable.
	{"2606:4700:4700::1111", true, "public"},
	{"2001:4860:4860::8888", true, "public"},
	{"2001:200::1", true, "just above IETF protocol assignments"},
	{"2a00:1450::1", true, "public"},
	{"2606:4700::1111%eth0", false, "zoned, so link-scoped whatever the address"},
}

func TestPublic(t *testing.T) {
	if n := len(publicCases); n < 40 {
		t.Fatalf("only %d cases; the table must cover every range", n)
	}
	for _, c := range publicCases {
		a, err := netip.ParseAddr(c.addr)
		if err != nil {
			t.Fatalf("test bug: %q is not an address", c.addr)
		}
		if got := Public(a); got != c.want {
			t.Errorf("Public(%s) = %v, want %v — %s", c.addr, got, c.want, c.what)
		}
	}
	if Public(netip.Addr{}) {
		t.Error("the zero Addr is not an address and must not be public")
	}
}

// ── Host ────────────────────────────────────────────────────────────────────

// answer makes the resolver return addrs (or err) for one test.
func answer(t *testing.T, err error, addrs ...string) {
	t.Helper()
	prev := lookup
	lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		out := make([]netip.Addr, len(addrs))
		for i, s := range addrs {
			out[i] = netip.MustParseAddr(s)
		}
		return out, err
	}
	t.Cleanup(func() { lookup = prev })
}

func TestHostJudgesEveryAnswer(t *testing.T) {
	answer(t, nil, "93.184.216.34", "2606:4700:4700::1111")
	if err := Host(context.Background(), "example.com"); err != nil {
		t.Fatalf("a name answering only public addresses was refused: %v", err)
	}

	// One public address beside the target is the documented way past a check
	// that reads only the first answer, and whoever dials picks the answer.
	answer(t, nil, "93.184.216.34", "10.1.2.3")
	if err := Host(context.Background(), "split.example"); !errors.Is(err, ErrRefused) {
		t.Fatalf("a name that also answers 10.1.2.3: err = %v, want ErrRefused", err)
	}
	answer(t, nil, "64:ff9b::a9fe:a9fe")
	if err := Host(context.Background(), "nat64.example"); !errors.Is(err, ErrRefused) {
		t.Fatalf("a name answering NAT64 metadata: err = %v, want ErrRefused", err)
	}
}

func TestHostJudgesLiteralsAndLoopbackNamesWithoutALookup(t *testing.T) {
	answer(t, errors.New("the resolver must not be asked"))
	for _, h := range []string{"127.0.0.1", "::1", "169.254.169.254", "fd00:ec2::254", "localhost", "LOCALHOST.", "api.localhost", ""} {
		if err := Host(context.Background(), h); !errors.Is(err, ErrRefused) {
			t.Errorf("Host(%q) = %v, want ErrRefused", h, err)
		}
	}
	if err := Host(context.Background(), "8.8.8.8"); err != nil {
		t.Errorf("Host(8.8.8.8) = %v, want nil", err)
	}
}

// A name that does not resolve is an outage, not an attack, and says so.
func TestHostResolutionFailureIsNotARefusal(t *testing.T) {
	answer(t, errors.New("no such host"))
	err := Host(context.Background(), "gone.example")
	if err == nil || errors.Is(err, ErrRefused) {
		t.Fatalf("err = %v, want a resolution error that is not ErrRefused", err)
	}
	answer(t, nil)
	if err := Host(context.Background(), "empty.example"); err == nil {
		t.Fatal("a name with no address was accepted")
	}
}

// ── Client ──────────────────────────────────────────────────────────────────

// admit lets the client dial exactly these loopback servers, as if they were
// public, for one test. Every other address is judged by Public.
func admit(t *testing.T, servers ...*httptest.Server) {
	t.Helper()
	ok := map[netip.AddrPort]bool{}
	for _, s := range servers {
		ok[netip.MustParseAddrPort(s.Listener.Addr().String())] = true
	}
	prev := permit
	permit = func(ap netip.AddrPort) bool { return ok[ap] || Public(ap.Addr()) }
	t.Cleanup(func() { permit = prev })
}

// port is the port a test server listens on.
func port(s *httptest.Server) string {
	return strconv.Itoa(int(netip.MustParseAddrPort(s.Listener.Addr().String()).Port()))
}

func serve(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return s
}

// A public URL that 302s inward is refused at the hop that matters, because the
// hop is a new dial and the dial is where the address is judged.
func TestClientRefusesARedirectInward(t *testing.T) {
	var reached atomic.Int32
	inside := serve(t, func(http.ResponseWriter, *http.Request) { reached.Add(1) })
	for _, to := range []string{
		inside.URL + "/admin",
		"http://localhost:" + port(inside) + "/admin",
		"http://169.254.169.254/latest/meta-data/",
	} {
		outside := serve(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, to, http.StatusFound)
		})
		admit(t, outside)
		_, err := Client(Options{Timeout: 5 * time.Second, Redirects: 5}).Get(outside.URL)
		if !errors.Is(err, ErrRefused) {
			t.Errorf("redirect to %s: err = %v, want ErrRefused", to, err)
		}
	}
	if n := reached.Load(); n != 0 {
		t.Fatalf("the loopback server was reached %d times", n)
	}
}

// A name is judged on what it resolved to, at the dial.
func TestClientRefusesALoopbackName(t *testing.T) {
	srv := serve(t, func(http.ResponseWriter, *http.Request) {
		t.Error("a loopback server was reached through its name")
	})
	_, err := Client(Options{Timeout: 5 * time.Second}).Get("http://localhost:" + port(srv) + "/")
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("err = %v, want ErrRefused", err)
	}
}

// A proxy from the environment would take the dial and the check with it, so the
// client never asks the environment.
func TestClientIgnoresTheEnvironmentProxy(t *testing.T) {
	var hits atomic.Int32
	proxy := serve(t, func(http.ResponseWriter, *http.Request) { hits.Add(1) })
	admit(t, proxy)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	t.Setenv("REQUEST_METHOD", "")

	const target = "http://192.0.2.1/latest/meta-data/"
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The control: the environment really does name the proxy for this URL, so a
	// client built on http.DefaultTransport would hand the request to it, and the
	// proxy — not the dialer — would decide where it goes. Read afresh: net/http
	// reads the environment once per process.
	if u, err := httpproxy.FromEnvironment().ProxyFunc()(req.URL); err != nil || u == nil || u.Host != proxy.Listener.Addr().String() {
		t.Fatalf("test setup: the environment does not route %s through the proxy (got %v, %v)", target, u, err)
	}

	_, err = Client(Options{Timeout: 5 * time.Second}).Do(req)
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("err = %v, want ErrRefused from dialling the target itself", err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the environment's proxy was used %d times", n)
	}
}

var secrets = []string{"Authorization", "Cookie", "X-Api-Key", "X-Tenant-Key"}

// credentialed builds a GET carrying every secret header and one that is not.
func credentialed(t *testing.T, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range secrets {
		req.Header.Set(h, "secret-"+h)
	}
	req.Header.Set("X-Trace", "trace")
	return req
}

// record answers /landed by sending what it received on the channel, and
// redirects everything else to the address its path names.
func record(t *testing.T, seen chan<- http.Header, next func(path string) string) *httptest.Server {
	t.Helper()
	return serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/landed" {
			seen <- r.Header.Clone()
			return
		}
		http.Redirect(w, r, next(r.URL.Path), http.StatusFound)
	})
}

func TestClientDropsSecretsWhenARedirectLeavesTheOrigin(t *testing.T) {
	seen := make(chan http.Header, 1)
	// Both servers are 127.0.0.1, one port apart. Go's own client keeps
	// Authorization and Cookie across that hop, because the HOST did not change.
	other := record(t, seen, nil)
	first := serve(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/landed", http.StatusFound)
	})
	admit(t, first, other)

	resp, err := Client(Options{Timeout: 5 * time.Second, Redirects: 1, Secret: []string{"X-Tenant-Key"}}).Do(credentialed(t, first.URL))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	h := <-seen
	for _, k := range secrets {
		if v := h.Get(k); v != "" {
			t.Errorf("%s crossed to another origin: %q", k, v)
		}
	}
	if h.Get("X-Trace") != "trace" {
		t.Error("a header that is not a secret was dropped too")
	}
}

func TestClientKeepsSecretsWithinTheOrigin(t *testing.T) {
	seen := make(chan http.Header, 1)
	var srv *httptest.Server
	srv = record(t, seen, func(string) string { return srv.URL + "/landed" })
	admit(t, srv)

	resp, err := Client(Options{Timeout: 5 * time.Second, Redirects: 1, Secret: []string{"X-Tenant-Key"}}).Do(credentialed(t, srv.URL+"/start"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	h := <-seen
	for _, k := range secrets {
		if h.Get(k) != "secret-"+k {
			t.Errorf("%s was dropped on a same-origin redirect", k)
		}
	}
}

// Back at the first origin after a detour, the secrets stay dropped: the origin
// in between chose that hop, path and all.
func TestClientKeepsSecretsDroppedAfterADetour(t *testing.T) {
	seen := make(chan http.Header, 1)
	var first *httptest.Server
	other := serve(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, first.URL+"/landed", http.StatusFound)
	})
	first = record(t, seen, func(string) string { return other.URL + "/bounce" })
	admit(t, first, other)

	resp, err := Client(Options{Timeout: 5 * time.Second, Redirects: 2, Secret: []string{"X-Tenant-Key"}}).Do(credentialed(t, first.URL+"/start"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	h := <-seen
	for _, k := range secrets {
		if v := h.Get(k); v != "" {
			t.Errorf("%s came back to the first origin after a detour: %q", k, v)
		}
	}
}

func TestClientCapsRedirects(t *testing.T) {
	var srv *httptest.Server
	srv = serve(t, func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/"))
		if n == 3 {
			return
		}
		http.Redirect(w, r, srv.URL+"/"+strconv.Itoa(n+1), http.StatusFound)
	})
	admit(t, srv)

	resp, err := Client(Options{Timeout: 5 * time.Second, Redirects: 3}).Get(srv.URL + "/0")
	if err != nil {
		t.Fatalf("three redirects under a limit of three: %v", err)
	}
	resp.Body.Close()
	for _, limit := range []int{0, 2} {
		if _, err := Client(Options{Timeout: 5 * time.Second, Redirects: limit}).Get(srv.URL + "/0"); err == nil {
			t.Errorf("three redirects under a limit of %d succeeded", limit)
		}
	}
}

func TestClientRefusesARedirectToAnotherScheme(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "file:///etc/passwd", http.StatusFound)
	})
	admit(t, srv)
	if _, err := Client(Options{Timeout: 5 * time.Second, Redirects: 5}).Get(srv.URL); !errors.Is(err, ErrRefused) {
		t.Fatalf("err = %v, want ErrRefused", err)
	}
}

func TestClientCapsTheBody(t *testing.T) {
	const limit = 4 << 10
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		_, _ = io.WriteString(w, strings.Repeat("x", n))
	})
	admit(t, srv)
	c := Client(Options{Timeout: 5 * time.Second, Limit: limit})

	read := func(n int) ([]byte, error) {
		resp, err := c.Get(srv.URL + "/?n=" + strconv.Itoa(n))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return io.ReadAll(resp.Body)
	}
	if b, err := read(limit); err != nil || len(b) != limit {
		t.Fatalf("a body of exactly the limit: %d bytes, err %v", len(b), err)
	}
	if b, err := read(limit + 1); !errors.Is(err, ErrTooLarge) || len(b) > limit {
		t.Fatalf("a body one byte over the limit: %d bytes, err %v, want ErrTooLarge", len(b), err)
	}
	if _, err := read(10 * limit); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("a body ten times the limit: err %v, want ErrTooLarge", err)
	}
}
