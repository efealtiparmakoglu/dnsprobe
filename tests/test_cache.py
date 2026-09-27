import os
import tempfile
import unittest

from dnsprobe.cache import DNSCache

BASE = 1_000_000  # fake clock start

def rr_a(ttl, ip="192.0.2.1", name="example.com."):
    return {"name": name, "type": 1, "type_name": "A", "class": 1,
            "ttl": ttl, "rdata": ip}


class FakeClock:
    def __init__(self):
        self.t = BASE
    def __call__(self):
        return self.t


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.cache = DNSCache(now=self.clock)

    def test_put_and_get(self):
        self.cache.put("example.com", 1, [rr_a(300)])
        got = self.cache.get("example.com", 1)
        self.assertEqual(got[0]["rdata"], "192.0.2.1")
        self.assertEqual(got[0]["ttl"], 300)

    def test_key_case_and_trailing_dot_insensitive(self):
        self.cache.put("Example.COM.", 1, [rr_a(300)])
        self.assertIsNotNone(self.cache.get("example.com", 1))
        self.assertIsNotNone(self.cache.get("EXAMPLE.com.", 1))

    def test_expiry(self):
        self.cache.put("example.com", 1, [rr_a(300)])
        self.clock.t += 299
        self.assertIsNotNone(self.cache.get("example.com", 1))
        self.clock.t += 1
        self.assertIsNone(self.cache.get("example.com", 1))

    def test_ttl_rewritten_to_remaining(self):
        self.cache.put("example.com", 1, [rr_a(300)])
        self.clock.t += 100
        got = self.cache.get("example.com", 1)
        self.assertEqual(got[0]["ttl"], 200)

    def test_zero_ttl_not_stored(self):
        self.cache.put("example.com", 1, [rr_a(0)])
        self.assertEqual(len(self.cache), 0)

    def test_min_ttl_wins(self):
        self.cache.put("example.com", 1, [rr_a(300), rr_a(60, ip="192.0.2.2")])
        self.clock.t += 61
        self.assertIsNone(self.cache.get("example.com", 1))

    def test_different_qtype_isolated(self):
        self.cache.put("example.com", 1, [rr_a(300)])
        self.assertIsNone(self.cache.get("example.com", 28))

    def test_lru_eviction(self):
        small = DNSCache(maxsize=2, now=self.clock)
        small.put("a.test", 1, [rr_a(300, name="a.test.")])
        small.put("b.test", 1, [rr_a(300, name="b.test.")])
        small.get("a.test", 1)          # touch a -> b becomes LRU
        small.put("c.test", 1, [rr_a(300, name="c.test.")])
        self.assertIsNotNone(small.get("a.test", 1))
        self.assertIsNone(small.get("b.test", 1))
        self.assertIsNotNone(small.get("c.test", 1))

    def test_prune(self):
        self.cache.put("a.test", 1, [rr_a(10, name="a.test.")])
        self.cache.put("b.test", 1, [rr_a(1000, name="b.test.")])
        self.clock.t += 10
        self.assertEqual(self.cache.prune(), 1)
        self.assertEqual(len(self.cache), 1)

    def test_get_gets_copy_not_internal_state(self):
        self.cache.put("example.com", 1, [rr_a(300)])
        got = self.cache.get("example.com", 1)
        got[0]["ttl"] = 1
        self.assertEqual(self.cache.get("example.com", 1)[0]["ttl"], 300)

    def test_save_and_load_roundtrip(self):
        self.cache.put("example.com", 1, [rr_a(300)])
        self.cache.put("gone.test", 1, [rr_a(1, name="gone.test.")])
        self.clock.t += 5  # 'gone.test' (ttl 1) expires, other one has 295 left
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "cache.json")
            self.cache.save(path)
            loaded = DNSCache.load(path, now=self.clock)
        self.assertIsNotNone(loaded.get("example.com", 1))
        self.assertIsNone(loaded.get("gone.test", 1))

    def test_load_skips_expired_and_caps_size(self):
        self.cache.put("a.test", 1, [rr_a(300, name="a.test.")])
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "cache.json")
            self.cache.save(path)
            self.clock.t += 1000  # everything expired on disk
            loaded = DNSCache.load(path, now=self.clock)
        self.assertEqual(len(loaded), 0)


if __name__ == "__main__":
    unittest.main()
