"""TTL-aware LRU cache for DNS answers. Positive caching only."""
import json
import time
from collections import OrderedDict


class DNSCache:
    def __init__(self, maxsize=4096, now=time.time):
        self.maxsize = maxsize
        self.now = now
        self._entries = OrderedDict()

    @staticmethod
    def _key(name, qtype):
        return (name.rstrip(".").lower(), int(qtype))

    def get(self, name, qtype):
        """Return a fresh copy of cached rrs (ttl rewritten to remaining),
        or None if absent/expired."""
        key = self._key(name, qtype)
        item = self._entries.get(key)
        if item is None:
            return None
        stored_at, expire_at, rrs = item
        current = self.now()
        if current >= expire_at:
            del self._entries[key]
            return None
        self._entries.move_to_end(key)
        remaining = max(int(expire_at - current), 0)
        elapsed = int(current - stored_at)
        return [dict(rr, ttl=max(rr["ttl"] - elapsed, 0)) for rr in rrs]

    def put(self, name, qtype, rrs, ttl=None):
        """Store records; ttl defaults to the minimum of the records."""
        if not rrs and ttl is None:
            return
        effective = ttl if ttl is not None else min(rr["ttl"] for rr in rrs)
        if effective <= 0:
            return
        key = self._key(name, qtype)
        current = self.now()
        self._entries[key] = (current, current + effective, list(rrs))
        self._entries.move_to_end(key)
        while len(self._entries) > self.maxsize:
            self._entries.popitem(last=False)

    def prune(self):
        """Drop expired entries; returns how many were removed."""
        current = self.now()
        expired = [k for k, (_, exp, _) in self._entries.items() if current >= exp]
        for key in expired:
            del self._entries[key]
        return len(expired)

    def save(self, path):
        """Persist to JSON; expired entries are skipped."""
        current = self.now()
        entries = []
        for (name, qtype), (_, expire_at, rrs) in self._entries.items():
            if current < expire_at:
                entries.append({"name": name, "qtype": qtype,
                                "expire_at": expire_at, "rrs": rrs})
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"version": 1, "entries": entries}, fh)

    @classmethod
    def load(cls, path, maxsize=4096, now=time.time):
        """Restore from JSON written by save(); expired entries are dropped."""
        cache = cls(maxsize=maxsize, now=now)
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        current = now()
        for entry in data.get("entries", []):
            if current < entry["expire_at"]:
                key = cache._key(entry["name"], entry["qtype"])
                cache._entries[key] = (current, entry["expire_at"], entry["rrs"])
        while len(cache._entries) > cache.maxsize:
            cache._entries.popitem(last=False)
        return cache

    def __len__(self):
        return len(self._entries)
