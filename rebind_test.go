// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package outbound

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// rebinder is a DNS server for one name that answers its first A query with a
// public address and every later one with loopback: the rebinding attack, where
// the check and the connect each ask and each get the answer the attacker chose.
// AAAA queries get no records, so the A sequence is the whole story.
type rebinder struct {
	conn  net.PacketConn
	asked atomic.Int32
	first netip.Addr
	later netip.Addr
}

func newRebinder(t *testing.T, first, later string) *rebinder {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &rebinder{conn: conn, first: netip.MustParseAddr(first), later: netip.MustParseAddr(later)}
	t.Cleanup(func() { _ = conn.Close() })
	go r.serve()
	return r
}

func (r *rebinder) serve() {
	buf := make([]byte, 1500)
	for {
		n, from, err := r.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		var p dnsmessage.Parser
		h, err := p.Start(buf[:n])
		if err != nil {
			continue
		}
		q, err := p.Question()
		if err != nil {
			continue
		}
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true})
		b.EnableCompression()
		_ = b.StartQuestions()
		_ = b.Question(q)
		_ = b.StartAnswers()
		if q.Type == dnsmessage.TypeA {
			a := r.later
			if r.asked.Add(1) == 1 {
				a = r.first
			}
			_ = b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 0}, dnsmessage.AResource{A: a.As4()})
		}
		msg, err := b.Finish()
		if err != nil {
			continue
		}
		_, _ = r.conn.WriteTo(msg, from)
	}
}

// resolve points both resolvers — Host's lookup and Client's dialer — at r for one
// test.
func (r *rebinder) resolve(t *testing.T) {
	t.Helper()
	res := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", r.conn.LocalAddr().String())
	}}
	prevLookup, prevResolver := lookup, resolver
	lookup, resolver = res.LookupNetIP, res
	t.Cleanup(func() { lookup, resolver = prevLookup, prevResolver })
}

// A check made before the fetch reads one answer and the fetch connects on
// another. Host on its own passes the first, public answer — that is the window a
// check-then-fetch leaves open — and Client, which judges the address it actually
// connects to, refuses the loopback the second lookup returns.
func TestClientRefusesARebindingName(t *testing.T) {
	var reached atomic.Int32
	inside := serve(t, func(http.ResponseWriter, *http.Request) { reached.Add(1) })
	r := newRebinder(t, "93.184.216.34", "127.0.0.1")
	r.resolve(t)

	if err := Host(context.Background(), "rebind.example"); err != nil {
		t.Fatalf("test setup: the first answer is public, so the check passes: %v", err)
	}
	_, err := Client(Options{Timeout: 5 * time.Second}).Get("http://rebind.example:" + port(inside) + "/latest/meta-data/")
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("err = %v, want ErrRefused for the loopback the dial resolved", err)
	}
	if n := reached.Load(); n != 0 {
		t.Fatalf("the loopback server was reached %d times through a rebinding name", n)
	}
	if n := r.asked.Load(); n < 2 {
		t.Fatalf("the name was resolved %d times; the dial must resolve it again", n)
	}
}

// A redirect is a new dial, so the hop resolves the name again: a public first
// answer buys the attacker nothing on the second hop either.
func TestClientRefusesARedirectToARebindingName(t *testing.T) {
	var reached atomic.Int32
	inside := serve(t, func(http.ResponseWriter, *http.Request) { reached.Add(1) })
	r := newRebinder(t, "127.0.0.1", "127.0.0.1")
	r.resolve(t)
	outside := serve(t, func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "http://rebind.example:"+port(inside)+"/", http.StatusFound)
	})
	admit(t, outside)
	_, err := Client(Options{Timeout: 5 * time.Second, Redirects: 5}).Get(outside.URL)
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("err = %v, want ErrRefused", err)
	}
	if n := reached.Load(); n != 0 {
		t.Fatalf("the loopback server was reached %d times", n)
	}
}
