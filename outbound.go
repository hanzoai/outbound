// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package outbound is the one way a Hanzo service reaches an address a tenant
// supplied.
//
// A URL a tenant hands us is dialled from INSIDE the cluster: next to the pod
// network, in-namespace service DNS, and a metadata endpoint that hands out
// credentials to anyone who asks. Every surface that fetches such a URL is a
// request-forgery primitive by construction, so "may this address be reached"
// has one answer, and it is here:
//
//   - Public says whether an address is on the public internet.
//   - Client is an http.Client that connects only to public addresses, judged
//     on the address the socket actually connects to.
//   - Host judges a name for a caller that hands the URL to something else to
//     dial — git, a headless browser, client-go. It judges that name only; what
//     the other dialler reaches on its own needs a bound of its own.
//
// It is for TENANT-SUPPLIED addresses. A service the deployment configured — a
// plane, an in-cluster sibling, a crawl browser — is private by design and is
// reached with a plain client; refusing it would protect nobody.
//
// It imports nothing but the standard library, so hanzo-inc/cloud, hanzoai/ai,
// hanzoai/iam and anything else that fetches a tenant's URL link the same rule.
package outbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"syscall"
	"time"
)

// ErrRefused is the refusal: an address that is not Public, a name that answers
// with one, or a redirect to a scheme other than http and https. It is a sentinel
// so a caller can tell an attack from an outage; a log line that cannot tell them
// apart makes one look like the other.
var ErrRefused = errors.New("outbound: refused")

// ErrTooLarge is a response body read past Options.Limit.
var ErrTooLarge = errors.New("outbound: response body exceeds the limit")

// special4 is the IANA IPv4 Special-Purpose Address Registry (RFC 6890 and its
// updates), plus multicast, which has a registry of its own.
var special4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network" (RFC 791)
	netip.MustParsePrefix("10.0.0.0/8"),      // private-use (RFC 1918)
	netip.MustParsePrefix("100.64.0.0/10"),   // shared address space, CGNAT (RFC 6598); Alibaba metadata 100.100.100.200
	netip.MustParsePrefix("127.0.0.0/8"),     // loopback (RFC 1122)
	netip.MustParsePrefix("169.254.0.0/16"),  // link-local (RFC 3927); the metadata endpoint 169.254.169.254
	netip.MustParsePrefix("172.16.0.0/12"),   // private-use (RFC 1918)
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments (RFC 6890); Oracle metadata 192.0.0.192
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation, TEST-NET-1 (RFC 5737)
	netip.MustParsePrefix("192.31.196.0/24"), // AS112-v4 (RFC 7535)
	netip.MustParsePrefix("192.52.193.0/24"), // AMT (RFC 7450)
	netip.MustParsePrefix("192.88.99.0/24"),  // deprecated 6to4 relay anycast (RFC 7526)
	netip.MustParsePrefix("192.168.0.0/16"),  // private-use (RFC 1918)
	netip.MustParsePrefix("192.175.48.0/24"), // direct delegation AS112 (RFC 7534)
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking (RFC 2544)
	netip.MustParsePrefix("198.51.100.0/24"), // documentation, TEST-NET-2 (RFC 5737)
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation, TEST-NET-3 (RFC 5737)
	netip.MustParsePrefix("224.0.0.0/4"),     // multicast (RFC 5771)
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved (RFC 1112), with 255.255.255.255 limited broadcast (RFC 919)
}

// unicast6 is the block IANA allocates IPv6 global unicast from (RFC 4291 §2.4).
// Nothing outside it is public, which refuses ::, ::1, IPv4-compatible ::/96,
// NAT64 64:ff9b::/96 and 64:ff9b:1::/48, discard 100::/64, 5f00::/16,
// fc00::/7, fe80::/10, fec0::/10 and ff00::/8 without listing them.
var unicast6 = netip.MustParsePrefix("2000::/3")

// special6 is the IANA IPv6 Special-Purpose Address Registry inside 2000::/3.
var special6 = []netip.Prefix{
	netip.MustParsePrefix("2001::/23"),         // IETF protocol assignments (RFC 2928): Teredo 2001::/32, anycast, benchmarking, AMT, AS112, ORCHID
	netip.MustParsePrefix("2001:db8::/32"),     // documentation (RFC 3849)
	netip.MustParsePrefix("2002::/16"),         // 6to4 (RFC 3056), deprecated (RFC 7526)
	netip.MustParsePrefix("2620:4f:8000::/48"), // direct delegation AS112 (RFC 7534)
	netip.MustParsePrefix("3fff::/20"),         // documentation (RFC 9637)
}

// Public reports whether a is an address a tenant-supplied URL may reach: false
// for every prefix in the IANA special-purpose registries and for multicast, true
// for the rest of the unicast internet.
//
// It is written against the registries rather than net.IP's predicates, because
// IsPrivate is RFC 1918 and ULA only, and IsGlobalUnicast admits CGNAT, the
// benchmarking and documentation blocks, 240/4 and every IPv6 spelling of a
// private IPv4 address.
//
// An IPv4-mapped address (::ffff:0:0/96) is judged as the IPv4 it maps. Every
// other IPv6 prefix that embeds an IPv4 address is refused whole, whatever it
// carries: NAT64 64:ff9b::/96 and 64:ff9b:1::/48 (so 64:ff9b::a9fe:a9fe, the
// metadata endpoint, never reaches a translator), 6to4 2002::/16, Teredo
// 2001::/32 and IPv4-compatible ::/96. A zoned address is link-scoped and
// refused.
func Public(a netip.Addr) bool {
	a = a.Unmap()
	switch {
	case !a.IsValid() || a.Zone() != "":
		return false
	case a.Is4():
		return !slices.ContainsFunc(special4, func(p netip.Prefix) bool { return p.Contains(a) })
	case !unicast6.Contains(a):
		return false
	}
	return !slices.ContainsFunc(special6, func(p netip.Prefix) bool { return p.Contains(a) })
}

// lookup is the resolver Host asks. A variable so this package's tests can hand
// it a hostile answer; nothing else assigns it.
var lookup = net.DefaultResolver.LookupNetIP

// resolver is the resolver Client's dialer asks. A variable so this package's tests
// can stand up a name that answers one address and then another; nothing else
// assigns it.
var resolver = net.DefaultResolver

// Host refuses a hostname that is unsafe to hand to a dialler this package does
// not control. An IP literal is judged as itself; "localhost" and *.localhost
// (RFC 6761) are refused without a lookup; any other name is resolved and refused
// if ANY answer is not Public, because that dialler, not us, picks the answer it
// connects to.
//
// It judges one instant, so it cannot stop a name that answers differently when
// the other dialler resolves it (DNS rebinding). Where the request is ours to
// make, Client closes that gap by judging the address actually connected. Nor
// does it see where that dialler goes next: a redirect, a frame, a proxy.
func Host(ctx context.Context, host string) error {
	name := strings.TrimSuffix(strings.ToLower(host), ".")
	if name == "" {
		return fmt.Errorf("%w: empty host", ErrRefused)
	}
	if name == "localhost" || strings.HasSuffix(name, ".localhost") {
		return fmt.Errorf("%w: %s is a loopback name", ErrRefused, host)
	}
	if a, err := netip.ParseAddr(name); err == nil {
		if !Public(a) {
			return fmt.Errorf("%w: %s is not a public address", ErrRefused, a)
		}
		return nil
	}
	addrs, err := lookup(ctx, "ip", name)
	if err != nil {
		return fmt.Errorf("outbound: resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("outbound: %s has no address", host)
	}
	for _, a := range addrs {
		if !Public(a) {
			return fmt.Errorf("%w: %s resolves to %s", ErrRefused, host, a)
		}
	}
	return nil
}

// Options is what varies between callers. The zero value follows no redirects,
// caps no body and sets no deadline beyond the request's context.
type Options struct {
	// Timeout bounds one request end to end, redirects included. Zero is no bound
	// beyond the request's context, as with http.Client.
	Timeout time.Duration
	// Redirects is how many redirects are followed; the next one is an error.
	Redirects int
	// Secret names headers, beyond Authorization, Cookie and X-Api-Key, that
	// carry a credential. See Client.
	Secret []string
	// Limit caps the response body in bytes. A read past it fails with
	// ErrTooLarge rather than returning a truncated body. Zero is no cap.
	Limit int64
}

// secret is dropped on every client's cross-origin redirect. Go's own client
// drops Authorization and Cookie only when the HOST changes — not the port or the
// scheme — and never X-Api-Key.
var secret = []string{"Authorization", "Cookie", "X-Api-Key"}

// Client returns an http.Client that reaches only Public addresses.
//
//   - The address is judged at DIAL time, in the dialer's Control hook, on the IP
//     and port the socket is about to connect to. Resolution has already
//     happened, so a name cannot pass one lookup and connect on another.
//   - Proxy is nil. A proxy from the environment takes the dial, and the check
//     with it: the client would connect to the proxy and the proxy would reach
//     whatever the URL names.
//   - Every redirect is a new dial, judged the same way, held to http and https,
//     and counted against Options.Redirects.
//   - Once a redirect leaves the first request's origin (scheme, host and port),
//     the secret headers are dropped for the rest of the chain, a hop back
//     included: the origin in between chose that hop.
func Client(o Options) *http.Client {
	var rt http.RoundTripper = &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Resolver: resolver, Control: control}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	if o.Limit > 0 {
		rt = capped{next: rt, limit: o.Limit}
	}
	drop := append(slices.Clone(secret), o.Secret...)
	return &http.Client{
		Timeout:   o.Timeout,
		Transport: rt,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > o.Redirects {
				return fmt.Errorf("outbound: redirect %d exceeds the limit of %d", len(via), o.Redirects)
			}
			if s := req.URL.Scheme; s != "http" && s != "https" {
				return fmt.Errorf("%w: redirect to scheme %q", ErrRefused, s)
			}
			if crossed(req, via) {
				for _, h := range drop {
					req.Header.Del(h)
				}
			}
			return nil
		},
	}
}

// permit is the dial-time decision. A variable only so this package's tests can
// admit the loopback server a redirect starts from; nothing else assigns it.
var permit = func(ap netip.AddrPort) bool { return Public(ap.Addr()) }

// control runs after resolution, on the literal address about to be connected.
func control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: unparseable address %q", ErrRefused, address)
	}
	if !permit(ap) {
		return fmt.Errorf("%w: %s is not a public address", ErrRefused, ap.Addr())
	}
	return nil
}

// crossed reports whether the chain has left the origin its first request went to.
func crossed(req *http.Request, via []*http.Request) bool {
	first := origin(via[0].URL)
	if origin(req.URL) != first {
		return true
	}
	return slices.ContainsFunc(via[1:], func(r *http.Request) bool { return origin(r.URL) != first })
}

// origin is scheme, host and port (RFC 6454), the port defaulted by scheme.
func origin(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	return u.Scheme + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

// capped wraps every response body in a reader that refuses to read past limit.
type capped struct {
	next  http.RoundTripper
	limit int64
}

func (c capped) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := c.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &body{ReadCloser: resp.Body, left: c.limit}
	return resp, nil
}

// body reads at most left more bytes; one byte more is ErrTooLarge.
type body struct {
	io.ReadCloser
	left int64
}

func (b *body) Read(p []byte) (int, error) {
	if b.left < 0 {
		return 0, ErrTooLarge
	}
	// Ask for one byte past what is allowed, so a body of exactly the limit ends
	// in io.EOF and a body one byte longer ends in ErrTooLarge.
	if int64(len(p)) > b.left+1 {
		p = p[:b.left+1]
	}
	n, err := b.ReadCloser.Read(p)
	if int64(n) <= b.left {
		b.left -= int64(n)
		return n, err
	}
	n = int(b.left)
	b.left = -1
	return n, ErrTooLarge
}
