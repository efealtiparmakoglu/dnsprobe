"""Iterative DNS resolver: root hints -> TLD -> authoritative, walking
referrals itself (RD=0) the way a recursive server does. Optionally falls
back to direct mode against given --server entries with RD=1.

The transport is injectable so the whole descent is testable offline.
"""
import socket
import time

from .cache import DNSCache
from .packet import (TYPE_A, TYPE_CNAME, TYPE_NS, TYPE_CODES, TYPE_NAMES,
                     build_query, parse_message)

ROOT_SERVERS = [
    "198.41.0.4",    # a.root-servers.net
    "170.247.170.2", # b.root-servers.net
    "192.33.4.12",   # c.root-servers.net
    "199.7.91.13",   # d.root-servers.net
    "192.203.230.10",# e.root-servers.net
    "192.5.5.241",   # f.root-servers.net
    "192.112.36.4",  # g.root-servers.net
    "198.97.190.53", # h.root-servers.net
]

DNS_PORT = 53
MAX_HOPS = 16
MAX_NS_DEPTH = 3


class ResolutionError(Exception):
    """Raised when a name cannot be resolved and why."""


class Resolver:
    def __init__(self, servers=None, timeout=2.0, retries=1, cache=None,
                 transport=None, now=time.time, max_hops=MAX_HOPS):
        self.servers = list(servers) if servers else None
        self.timeout = timeout
        self.retries = retries
        self.cache = cache if cache is not None else DNSCache(now=now)
        self.now = now
        self.max_hops = max_hops
        self.transport = transport if transport is not None else self._udp_transport

    @staticmethod
    def _udp_transport(server, payload, timeout):
        host, _, port_str = server.partition(":")
        port = int(port_str) if port_str else DNS_PORT
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(timeout)
            sock.sendto(payload, (host, port))
            data, _ = sock.recvfrom(65535)
            return data
        finally:
            sock.close()

    def resolve(self, name, qtype="A", _depth=0):
        """Resolve name/qtype. Returns the parsed response dict with two
        extra keys: _server (ip or 'cache') and _cached (bool)."""
        if _depth > MAX_NS_DEPTH:
            raise ResolutionError(f"resolution too deep at {name!r}")
        type_num = TYPE_CODES[qtype.upper()]
        qname = name.rstrip(".")
        servers = self.servers or ROOT_SERVERS
        rd = 1 if self.servers else 0
        seen_cnames = {qname.lower()}
        chain = []  # CNAME rrs followed so far, kept in the final answer
        hops = 0

        while hops < self.max_hops:
            hops += 1
            cached = self.cache.get(qname, type_num)
            if cached is not None:
                return self._assemble(name.rstrip("."), type_num,
                                      chain + cached, "cache", True)

            response, server_ip = self._query_servers(servers, qname, type_num, rd)
            if response["rcode"] != 0:
                raise ResolutionError(
                    f"{qname}/{TYPE_NAMES.get(type_num, type_num)}: "
                    f"{response['rcode_name']} from {server_ip}")

            answers = response["answers"]
            exact = [rr for rr in answers
                     if rr["type"] == type_num
                     and rr["name"].rstrip(".").lower() == qname.lower()]
            if exact:
                self.cache.put(qname, type_num, exact)
                return self._assemble(name.rstrip("."), type_num,
                                      chain + exact, server_ip, False)

            if type_num != TYPE_CNAME:
                cnames = [rr for rr in answers
                          if rr["type"] == TYPE_CNAME
                          and rr["name"].rstrip(".").lower() == qname.lower()]
                if cnames:
                    target = cnames[0]["rdata"].rstrip(".")
                    if target.lower() in seen_cnames:
                        raise ResolutionError(f"CNAME loop at {qname!r}")
                    seen_cnames.add(target.lower())
                    self.cache.put(qname, TYPE_CNAME, cnames)
                    in_answer = [rr for rr in answers
                                 if rr["type"] == type_num
                                 and rr["name"].rstrip(".").lower() == target.lower()]
                    if in_answer:
                        self.cache.put(target, type_num, in_answer)
                        return self._assemble(name.rstrip("."), type_num,
                                              chain + cnames + in_answer,
                                              server_ip, False)
                    chain += cnames
                    qname = target
                    servers = self.servers or ROOT_SERVERS
                    continue

            referral = self._glue_for(response)
            if referral and set(referral) != set(servers):
                servers = referral
                continue
            if response["authority"] and _depth < MAX_NS_DEPTH:
                ns_names = [rr["rdata"] for rr in response["authority"]
                            if rr["type"] == TYPE_NS]
                resolved = self._resolve_ns_names(ns_names, _depth)
                if resolved and set(resolved) != set(servers):
                    servers = resolved
                    continue
            raise ResolutionError(
                f"no answer and no referral for {qname}/"
                f"{TYPE_NAMES.get(type_num, type_num)} from {server_ip}")
        raise ResolutionError(f"gave up after {self.max_hops} hops on {name!r}")

    def _assemble(self, qname, type_num, answers, server, cached):
        return {
            "id": 0,
            "response": True,
            "rcode": 0,
            "rcode_name": "NOERROR",
            "authoritative": not cached,
            "questions": [{
                "name": qname + ".",
                "type": type_num,
                "type_name": TYPE_NAMES.get(type_num, str(type_num)),
                "class": 1,
                "class_name": "IN",
            }],
            "answers": answers,
            "authority": [],
            "additional": [],
            "_server": server,
            "_cached": cached,
        }

    @staticmethod
    def _glue_for(response):
        """Next hop from authority NS names + additional A glue."""
        ns_names = {rr["rdata"].rstrip(".").lower()
                    for rr in response["authority"] if rr["type"] == TYPE_NS}
        glue = {}
        for rr in response["additional"]:
            if rr["type"] == TYPE_A and rr["name"].rstrip(".").lower() in ns_names:
                glue[rr["name"].rstrip(".").lower()] = rr["rdata"]
        return [glue[name] for name in ns_names if name in glue]

    def _resolve_ns_names(self, ns_names, depth):
        """Resolve NS hostnames to addresses when a referral had no glue."""
        found = []
        for ns in ns_names[:2]:
            try:
                sub = self.resolve(ns.rstrip("."), "A", _depth=depth + 1)
            except ResolutionError:
                continue
            for rr in sub["answers"]:
                if rr["type"] == TYPE_A:
                    found.append(rr["rdata"])
        return found

    def _query_servers(self, servers, qname, type_num, rd):
        """Ask each server (with retries) until one answers with matching id."""
        errors = []
        for server in servers:
            for _ in range(self.retries + 1):
                qid = (int(self.now() * 1e6) * 1103515245 + 12345) & 0xFFFF
                payload = build_query(qid, qname, type_num, rd=rd)
                try:
                    raw = self.transport(server, payload, self.timeout)
                    response = parse_message(raw)
                    if response["id"] != qid:
                        raise ValueError("query id mismatch")
                    return response, server
                except (socket.timeout, TimeoutError, OSError,
                        ValueError) as exc:
                    errors.append(f"{server}: {exc}")
        raise ResolutionError("no usable response from " +
                              ", ".join(sorted(set(servers))) +
                              " (" + "; ".join(errors[-2:]) + ")")
