"""dnsprobe — educational DNS client: build/parse packets by hand, walk
referrals iteratively, cache answers by TTL, dump raw packets."""
import argparse
import json
import socket
import sys
import time

from . import __version__
from .cache import DNSCache
from .packet import DNSFormatError, TYPE_CODES, hexdump
from .resolver import ROOT_SERVERS, ResolutionError, Resolver

QUERY_TYPES = sorted(TYPE_CODES)


def _live_transport(server, payload, timeout):
    host, _, port_str = server.partition(":")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(payload, (host, int(port_str) if port_str else 53))
        data, _ = sock.recvfrom(65535)
        return data
    finally:
        sock.close()


def format_rr(rr):
    rdata = rr["rdata"]
    if isinstance(rdata, dict):
        if "mname" in rdata:
            rdata = (f"{rdata['mname']} {rdata['rname']} (serial {rdata['serial']} "
                     f"refresh {rdata['refresh']} retry {rdata['retry']} "
                     f"expire {rdata['expire']} min {rdata['minimum']})")
        elif "preference" in rdata:
            rdata = f"{rdata['preference']} {rdata['exchange']}"
    if isinstance(rdata, list):  # TXT strings
        rdata = " ".join(f'"{s}"' for s in rdata)
    return f"{rr['name']:<32} {rr['ttl']:>8}  IN  {rr['type_name']:<6} {rdata}"


def build_parser():
    parser = argparse.ArgumentParser(
        prog="dnsprobe",
        description="Educational DNS resolver: hand-built packets, iterative "
                    "referral walking, TTL cache, packet dump.")
    parser.add_argument("name", help="domain name to resolve")
    parser.add_argument("qtype", nargs="?", default="A",
                        choices=[t.lower() for t in QUERY_TYPES] + QUERY_TYPES,
                        help="record type (default A)")
    parser.add_argument("--server", action="append", metavar="IP[:PORT]",
                        help="query this server directly with RD=1 "
                             "(default: iterative from root hints); repeatable")
    parser.add_argument("--timeout", type=float, default=2.0,
                        help="per-query timeout seconds (default 2)")
    parser.add_argument("--retries", type=int, default=1,
                        help="retries per server (default 1)")
    parser.add_argument("--no-cache", action="store_true",
                        help="do not read or store answers in the cache")
    parser.add_argument("--cache-file", metavar="PATH",
                        help="persist the cache to PATH across runs")
    parser.add_argument("--cache-size", type=int, default=4096,
                        help="cache entry limit (default 4096)")
    parser.add_argument("--dump", action="store_true",
                        help="hexdump the raw query and response packets")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable output")
    parser.add_argument("--version", action="version",
                        version=f"dnsprobe {__version__}")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    qtype = args.qtype.upper()

    cache = DNSCache(maxsize=max(args.cache_size, 1))
    if args.cache_file:
        import os
        if os.path.exists(args.cache_file):
            try:
                cache = DNSCache.load(args.cache_file, maxsize=cache.maxsize)
            except (ValueError, OSError) as exc:
                print(f"dnsprobe: ignoring unreadable cache file: {exc}",
                      file=sys.stderr)

    last = {}
    transport = _live_transport
    if args.dump:
        def transport(server, payload, timeout):
            last["query"] = payload
            raw = _live_transport(server, payload, timeout)
            last["response"] = raw
            return raw

    resolver = Resolver(
        servers=args.server,
        timeout=args.timeout,
        retries=args.retries,
        cache=None if args.no_cache else cache,
        transport=transport,
    )

    started = time.monotonic()
    try:
        result = resolver.resolve(args.name, qtype)
    except ResolutionError as exc:
        print(f"dnsprobe: {exc}", file=sys.stderr)
        return 1
    except DNSFormatError as exc:
        print(f"dnsprobe: invalid name or packet: {exc}", file=sys.stderr)
        return 2
    elapsed_ms = int((time.monotonic() - started) * 1000)

    if args.cache_file:
        try:
            cache.save(args.cache_file)
        except OSError as exc:
            print(f"dnsprobe: could not save cache: {exc}", file=sys.stderr)

    result["_query_ms"] = elapsed_ms
    result["_name"] = args.name

    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    q = result["questions"][0]
    print(f"; <<>> dnsprobe {__version__} <<>> {args.name} {qtype}")
    print(f";; QUESTION\n{q['name']:<32} {'':>8}  IN  {q['type_name']}")
    if result["_cached"]:
        print(f";; ANSWER (from cache)")
    else:
        print(f";; ANSWER (from {result['_server']})")
    for rr in result["answers"]:
        print(format_rr(rr))
    if not result["answers"]:
        print("(empty)")
    print(f";; Query time: {elapsed_ms} ms · Server: {result['_server']} "
          f"· Cached: {'yes' if result['_cached'] else 'no'}")

    if args.dump:
        if "query" in last:
            print(f";; QUERY PACKET ({len(last['query'])} bytes)")
            print("\n".join(hexdump(last["query"])))
        print(f";; response captured via {result['_server']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
