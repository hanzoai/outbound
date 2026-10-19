# LLM.md — hanzoai/outbound

The one rule for reaching an address a tenant supplied. Standard library only,
`MIT OR Apache-2.0`, imported by every Hanzo service that fetches a URL someone
else wrote: hanzo-inc/cloud (webhooks, crawl, git mirror, destinations, sync,
research, auto, MCP tools, reference, script, fleet), hanzoai/ai (documents and
images a request names) and hanzoai/iam (identity-provider discovery, JWKS,
token and userinfo calls).

## The API

| name | use |
|---|---|
| `Public(netip.Addr) bool` | the address is on the public internet |
| `Client(Options) *http.Client` | a client that connects only to `Public` addresses |
| `Host(ctx, host) error` | judge a name for a dialler this package does not control |
| `ErrRefused`, `ErrTooLarge` | the refusal, and a body read past `Options.Limit` |

`Options`: `Timeout` (the whole request, redirects included), `Redirects` (how
many are followed; the next is an error), `Secret` (headers beyond Authorization,
Cookie and X-Api-Key dropped once a redirect leaves the first origin), `Limit`
(response body cap in bytes).

## Why it holds

- **The address is judged at the dial**, in `net.Dialer.Control`, on the IP the
  socket is about to connect to. Resolution has already happened, so the address
  checked IS the address connected: a name that answers public once and private
  the next time (DNS rebinding) is refused on the answer that would have been
  used. `TestClientRefusesARebindingName` runs a DNS server that does exactly
  that; a check made before the fetch (`Host`) passes it, the fetch does not.
- **Every redirect is a new dial**, judged the same way, held to http and https,
  and counted. A public URL that 302s to `169.254.169.254` or a rebinding name is
  refused at that hop.
- **No proxy.** A proxy from the environment would take the dial, and the check
  with it.
- **`Public` is the IANA special-purpose registries**, not `net.IP`'s predicates:
  `IsPrivate` is RFC 1918 and ULA only, and `IsGlobalUnicast` admits CGNAT,
  benchmarking, the TEST-NETs, 240/4 and every IPv6 spelling of a private IPv4
  address. IPv4-mapped IPv6 is judged as the IPv4; NAT64 (`64:ff9b::/96`,
  `64:ff9b:1::/48`), 6to4, Teredo and IPv4-compatible are refused whole, so
  `64:ff9b::a9fe:a9fe` never reaches a translator. Zoned addresses are refused.
  Metadata endpoints covered by name in the table: AWS (`169.254.169.254`,
  `fd00:ec2::254`), Alibaba (`100.100.100.200`), Oracle (`192.0.0.192`).

## For a caller

- A service the deployment configured (a plane, a sibling, an in-cluster
  browser) is private by design and is reached with a plain client.
- A test that must reach `httptest` on loopback replaces the CALLER's client
  variable with a plain one; this package has no switch that turns the rule off.
- `Host` judges one instant and cannot see where the other dialler goes next;
  prefer `Client` whenever the request is yours to make.

## Release

`v*` tags from `main`, patch bumps only. `go test ./...` is the gate.
