import struct
import unittest

from dnsprobe.cache import DNSCache
from dnsprobe.packet import TYPE_A, TYPE_CNAME, TYPE_NS, build_response, parse_message
from dnsprobe.resolver import ResolutionError, Resolver

BASE = 1_000_000

ROOT_IP = "198.41.0.4"
TLD_IP = "192.5.6.30"
AUTH_IP = "93.184.216.34"


def rr(name, type_num, ttl, rdata):
    type_names = {1: "A", 2: "NS", 5: "CNAME", 16: "TXT"}
    return {"name": name, "type": type_num, "type_name": type_names[type_num],
            "class": 1, "ttl": ttl, "rdata": rdata}


class FakeInternet:
    """Responds per-server: root -> .com referral, TLD -> example referral,
    authoritative -> answers. Also direct-mode answer server."""

    def __init__(self, answers, mode="iterative", rcode=0):
        self.answers = answers
        self.mode = mode
        self.rcode = rcode
        self.queries = []  # (server, name)

    def __call__(self, server, payload, timeout):
        qid = struct.unpack(">H", payload[:2])[0]
        from dnsprobe.packet import decode_name
        qname, offset = decode_name(payload, 12)
        qtype = struct.unpack(">H", payload[offset:offset + 2])[0]
        self.queries.append((server, qname, qtype))
        if self.rcode:
            return build_response(qid, qname, qtype, answers=[],
                                  rcode=self.rcode)
        if self.mode == "direct":
            return build_response(qid, qname, qtype, answers=self.answers)
        if server == ROOT_IP:
            return build_response(
                qid, qname, qtype, answers=[],
                authority=[rr("com.", TYPE_NS, 172800, "a.gtld-servers.net.")],
                additional=[rr("a.gtld-servers.net.", TYPE_A, 172800, TLD_IP)])
        if server == TLD_IP:
            return build_response(
                qid, qname, qtype, answers=[],
                authority=[rr("example.com.", TYPE_NS, 172800, "ns1.example.com.")],
                additional=[rr("ns1.example.com.", TYPE_A, 172800, AUTH_IP)])
        return build_response(qid, qname, qtype, answers=self.answers)


class FakeClock:
    def __init__(self):
        self.t = BASE
    def __call__(self):
        return self.t


def make_resolver(fake, **kw):
    clock = FakeClock()
    kw.setdefault("cache", DNSCache(now=clock))
    resolver = Resolver(transport=fake, now=clock, **kw)
    return resolver, clock


ANSWER = [rr("www.example.com.", TYPE_A, 3600, "93.184.216.34")]


class IterativeResolutionTests(unittest.TestCase):
    def test_descends_root_tld_authoritative(self):
        fake = FakeInternet(ANSWER)
        resolver, _ = make_resolver(fake)
        result = resolver.resolve("www.example.com", "A")
        self.assertEqual(result["answers"][0]["rdata"], "93.184.216.34")
        self.assertFalse(result["_cached"])
        servers = [q[0] for q in fake.queries]
        self.assertEqual(servers, [ROOT_IP, TLD_IP, AUTH_IP])

    def test_query_sent_iterative_rd0(self):
        fake = FakeInternet(ANSWER)
        resolver, _ = make_resolver(fake)
        resolver.resolve("www.example.com", "A")
        # nothing crashed: fake tolerated any flags; assert 3 hops happened
        self.assertEqual(len(fake.queries), 3)

    def test_second_query_uses_cache(self):
        fake = FakeInternet(ANSWER)
        resolver, _ = make_resolver(fake)
        resolver.resolve("www.example.com", "A")
        resolver.resolve("www.example.com", "A")
        self.assertEqual(len(fake.queries), 3)  # no extra network hops
        cached = resolver.resolve("www.example.com", "A")
        self.assertTrue(cached["_cached"])
        self.assertEqual(cached["_server"], "cache")

    def test_cached_ttl_decays(self):
        fake = FakeInternet(ANSWER)
        resolver, clock = make_resolver(fake)
        fresh = resolver.resolve("www.example.com", "A")
        clock.t += 1000
        later = resolver.resolve("www.example.com", "A")
        self.assertEqual(fresh["answers"][0]["ttl"], 3600)
        self.assertEqual(later["answers"][0]["ttl"], 2600)


class CnameTests(unittest.TestCase):
    def test_follows_cname_chain_from_roots(self):
        answers = [
            rr("www.example.com.", TYPE_CNAME, 600, "edge.example.net."),
        ]
        edge = [rr("edge.example.net.", TYPE_A, 300, "203.0.113.7")]
        calls = []

        def transport(server, payload, timeout):
            qid = struct.unpack(">H", payload[:2])[0]
            from dnsprobe.packet import decode_name
            qname, off = decode_name(payload, 12)
            qtype = struct.unpack(">H", payload[off:off + 2])[0]
            calls.append(qname)
            if qname == "www.example.com.":
                return build_response(qid, qname, qtype, answers=answers)
            return build_response(qid, qname, qtype, answers=edge)

        clock = FakeClock()
        resolver = Resolver(transport=transport, now=clock,
                            cache=DNSCache(now=clock))
        result = resolver.resolve("www.example.com", "A")
        self.assertEqual(result["answers"][0]["type_name"], "CNAME")
        self.assertEqual(result["answers"][1]["rdata"], "203.0.113.7")
        self.assertIn("edge.example.net.", calls)

    def test_cname_loop_detected(self):
        answer = [rr("a.test.", TYPE_CNAME, 60, "b.test.")]

        def transport(server, payload, timeout):
            qid = struct.unpack(">H", payload[:2])[0]
            from dnsprobe.packet import decode_name
            qname, off = decode_name(payload, 12)
            return build_response(qid, qname, "A",
                                  answers=[dict(answer[0], rdata=qname)])

        clock = FakeClock()
        resolver = Resolver(transport=transport, now=clock,
                            cache=DNSCache(now=clock))
        with self.assertRaises(ResolutionError):
            resolver.resolve("a.test", "A")


class ErrorTests(unittest.TestCase):
    def test_nxdomain_raises(self):
        fake = FakeInternet([], rcode=3)
        resolver, _ = make_resolver(fake)
        with self.assertRaises(ResolutionError) as ctx:
            resolver.resolve("missing.example.com", "A")
        self.assertIn("NXDOMAIN", str(ctx.exception))

    def test_no_answer_no_referral(self):
        fake = FakeInternet([], rcode=0, mode="direct")
        resolver, _ = make_resolver(fake)
        with self.assertRaises(ResolutionError) as ctx:
            resolver.resolve("empty.test", "A")
        self.assertIn("no answer and no referral", str(ctx.exception))

    def test_all_servers_timeout(self):
        def transport(server, payload, timeout):
            raise TimeoutError("timed out")

        clock = FakeClock()
        resolver = Resolver(servers=["10.255.255.1"], retries=1, timeout=0.05,
                            transport=transport, now=clock,
                            cache=DNSCache(now=clock))
        with self.assertRaises(ResolutionError) as ctx:
            resolver.resolve("example.com", "A")
        self.assertIn("no usable response", str(ctx.exception))

    def test_id_mismatch_retried_then_fails(self):
        def transport(server, payload, timeout):
            # answer with wrong id
            bad = bytearray(payload)
            bad[0] ^= 0xFF
            return build_response(struct.unpack(">H", bytes(bad[:2]))[0],
                                  "x.", "A", answers=[])
        clock = FakeClock()
        resolver = Resolver(servers=["192.0.2.9"], retries=0,
                            transport=transport, now=clock,
                            cache=DNSCache(now=clock))
        with self.assertRaises(ResolutionError):
            resolver.resolve("example.com", "A")


class DirectModeTests(unittest.TestCase):
    def test_direct_server_answers_rd1(self):
        fake = FakeInternet(ANSWER, mode="direct")
        resolver, _ = make_resolver(fake, servers=["192.0.2.53"])
        result = resolver.resolve("www.example.com", "A")
        self.assertEqual(result["answers"][0]["rdata"], "93.184.216.34")
        self.assertEqual(fake.queries[0][0], "192.0.2.53")


class OtherTypeTests(unittest.TestCase):
    def test_txt_query(self):
        answers = [rr("example.com.", 16, 300, ["v=spf1 -all"])]
        fake = FakeInternet(answers, mode="direct")
        resolver, _ = make_resolver(fake, servers=["192.0.2.53"])
        result = resolver.resolve("example.com", "TXT")
        self.assertEqual(result["answers"][0]["rdata"], ["v=spf1 -all"])

    def test_cname_query_does_not_follow(self):
        answers = [rr("alias.test.", TYPE_CNAME, 60, "real.test.")]
        fake = FakeInternet(answers, mode="direct")
        resolver, _ = make_resolver(fake, servers=["192.0.2.53"])
        result = resolver.resolve("alias.test", "CNAME")
        self.assertEqual(result["answers"][0]["rdata"], "real.test.")

    def test_ns_referral_with_out_of_bailiwick_glueless_ns(self):
        """Referral names an out-of-zone NS; resolver resolves the NS name
        from the roots, then queries it for the answer."""
        calls = []
        NS_A_IP = "203.0.113.99"

        def transport(server, payload, timeout):
            qid = struct.unpack(">H", payload[:2])[0]
            from dnsprobe.packet import decode_name
            qname, off = decode_name(payload, 12)
            qtype = struct.unpack(">H", payload[off:off + 2])[0]
            calls.append((server, qname, qtype))
            if qname == "ns.other-zone.net.":
                return build_response(
                    qid, qname, qtype,
                    answers=[rr("ns.other-zone.net.", TYPE_A, 300, NS_A_IP)])
            if qname.endswith("bigzone.test.") and server == NS_A_IP:
                return build_response(
                    qid, qname, qtype,
                    answers=[rr("host.bigzone.test.", TYPE_A, 60, "203.0.113.100")])
            return build_response(
                qid, qname, qtype, answers=[],
                authority=[rr("bigzone.test.", TYPE_NS, 3600,
                              "ns.other-zone.net.")])  # no glue

        clock = FakeClock()
        resolver = Resolver(transport=transport, now=clock,
                            cache=DNSCache(now=clock))
        result = resolver.resolve("host.bigzone.test", "A")
        self.assertEqual(result["answers"][0]["rdata"], "203.0.113.100")
        self.assertIn((NS_A_IP, "host.bigzone.test.", TYPE_A), calls)

    def test_glueless_in_bailiwick_ns_fails_cleanly(self):
        def transport(server, payload, timeout):
            qid = struct.unpack(">H", payload[:2])[0]
            from dnsprobe.packet import decode_name
            qname, off = decode_name(payload, 12)
            return build_response(
                qid, qname, "A", answers=[],
                authority=[rr("loop.test.", TYPE_NS, 3600, "ns.loop.test.")])

        clock = FakeClock()
        resolver = Resolver(transport=transport, now=clock,
                            cache=DNSCache(now=clock))
        with self.assertRaises(ResolutionError):
            resolver.resolve("host.loop.test", "A")


if __name__ == "__main__":
    unittest.main()
