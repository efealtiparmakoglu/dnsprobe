# dnsprobe

**Educational DNS resolver in pure Python — hand-built wire format, iterative referral walking from the root hints, TTL cache, packet dump. Zero dependencies.**

```
$ dnsprobe www.example.com
; <<>> dnsprobe 1.0.0 <<>> www.example.com A
;; QUESTION
www.example.com.                          IN  A
;; ANSWER (from 93.184.216.34)
www.example.com.                 86400  IN  A     93.184.216.34
;; Query time: 118 ms · Server: 93.184.216.34 · Cached: no

$ dnsprobe example.com MX --server 9.9.9.9 --dump
$ dnsprobe example.com A --json | jq '.answers[0].rdata'
```

Most "educational DNS" tools stop at sending one query to `8.8.8.8`. dnsprobe
does what a recursive resolver does: it asks a root server, reads the NS
referral for `.com`, walks to the TLD servers, reads the referral for the
domain, queries the authoritative server — building and parsing every packet
by hand on the way.

## Why dnsprobe

- **Wire format from scratch.** Header, question and resource records are
  packed/unpacked with `struct` per RFC 1035 — including compression-pointer
  parsing with loop and backwards-jump guards. A/AAAA/CNAME/NS/MX/TXT/SOA/PTR
  are decoded to real values; unknown types fall back to hex.
- **Iterative resolution.** Built-in root hints, glue-record chasing, and
  out-of-bailiwick NS names resolved on demand. CNAME chains are followed
  across servers (loops detected) and kept intact in the answer.
- **TTL cache.** Answers are cached under `(name, type)`; hits rewrite the
  TTL to the remaining seconds. `--cache-file` persists it across runs,
  `--cache-size` bounds it (LRU), zero-TTL records are never stored.
- **Packet dump.** `--dump` shows the raw query hexdump; every response can
  be inspected as JSON (`--json`) with per-record rdata.
- **Direct mode.** `--server IP[:PORT]` switches to RD=1 queries against a
  specific resolver — handy for testing local servers.
- **Honest errors.** NXDOMAIN/SERVFAIL/REFUSED surface with the server that
  sent them; no-glue referrals, CNAME loops and id mismatches all fail loudly.
- **Zero dependencies.** Standard library only — `socket`, `struct`, `json`.

## Usage

```sh
dnsprobe example.com                       # iterative resolution from roots
dnsprobe example.com AAAA                  # any of A AAAA CNAME NS MX TXT SOA PTR
dnsprobe example.com MX --server 9.9.9.9   # direct query, RD=1
dnsprobe example.com A --dump              # raw query packet hexdump
dnsprobe example.com A --json              # machine-readable
dnsprobe example.com A --cache-file ~/.dnsprobe-cache.json
dnsprobe example.com A --no-cache --timeout 1 --retries 2
```

Exit codes: 0 ok, 1 resolution failure (NXDOMAIN, timeout, referral dead end),
2 usage error (bad name, unknown type).

## Protocol notes

The UDP path never exceeds one 512-byte classic query: no EDNS, no DNSSEC
DO bit — responses with anything larger simply still parse if they fit in
64 KiB. Compression pointers are accepted while parsing (real servers use
them) but never emitted while building, which keeps every generated packet
byte-deterministic.

## Development

```sh
python3 -m unittest discover -s tests   # 71 tests, no network needed
```

The resolver takes an injectable transport and clock, so the whole
root → TLD → authoritative descent, CNAME chasing, cache decay and retry
behavior are tested offline against a fake DNS internet.

## License

MIT — see [LICENSE](LICENSE).
