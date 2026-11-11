# DNS Lookup

A free, single-page DNS record lookup. Live at [dns.hbenali.ovh](https://dns.hbenali.ovh).

No backend, no build step, no dependencies: static HTML, CSS and one small script calling a public DNS-over-HTTPS API from the browser.

## Features

- **Record types**: A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, CAA, HTTPS, SVCB, DS, DNSKEY, PTR, TLSA, plus an "All common types" button (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA in parallel)
- **IP input**: an IPv4 or IPv6 address is converted to its `in-addr.arpa` / `ip6.arpa` name and queried for PTR
- **Readable data**: TTL, MX priority, SOA fields with durations, CAA flags/tag/value, SRV priority/weight/port/target, TXT strings joined, DS/DNSKEY/TLSA fields named
- **Response status** (NOERROR, NXDOMAIN, SERVFAIL, REFUSED...) with a plain-English explanation, the DNSSEC AD flag, and the CNAME chain
- **Copy as text** of the results in zone-file style
- A short reference of what each record type is for, and links to the sibling tools (SPF, DKIM, DMARC, BIMI, DNSSEC, CAA, MX, SSL, RDAP, IP)
- Dark editorial design with a light mode, self-hosted fonts, PWA, strict CSP (`script-src 'self'`)

## Limits

- Answers come from Google Public DNS, not from the domain's authoritative servers: TTLs are remaining cache time, and AD is Google's DNSSEC validation result (AD false does not prove the zone is unsigned).
- A browser cannot do raw DNS, zone transfers (AXFR) or `ANY` queries; only what the DoH JSON API returns is shown.

## Running locally

```bash
python3 -m http.server 8080
# open http://localhost:8080
```

`?domain=example.com&type=MX` runs a lookup on load (`type=ALL` for the common types).

## Data sources

- [dns.google](https://developers.google.com/speed/public-dns/docs/doh): DNS-over-HTTPS JSON API

## Deployment

GitHub Pages, deployed on every push to `main` (see `.github/workflows/`).

## License

MIT, see [LICENSE](LICENSE).
