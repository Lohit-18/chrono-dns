"""TTL-aware LRU answer cache.

A resolver without a cache is a resolver that melts. This one is deliberately
simple and allocation-light: an OrderedDict keyed by (qname, qtype, qclass)
holding the raw upstream wire response plus its expiry.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass


@dataclass(slots=True)
class CacheEntry:
    payload: bytes
    expires_at: float
    hits: int = 0


class AnswerCache:
    def __init__(self, max_entries: int = 20_000, ttl_floor: int = 30,
                 ttl_ceiling: int = 3600) -> None:
        self.max_entries = max_entries
        self.ttl_floor = ttl_floor
        self.ttl_ceiling = ttl_ceiling
        self._data: OrderedDict[tuple, CacheEntry] = OrderedDict()
        self.hits = 0
        self.misses = 0
        self.evictions = 0

    def _key(self, qname: str, qtype: str) -> tuple:
        return (qname.lower().rstrip("."), qtype.upper())

    def get(self, qname: str, qtype: str) -> bytes | None:
        key = self._key(qname, qtype)
        entry = self._data.get(key)
        if entry is None:
            self.misses += 1
            return None
        if entry.expires_at <= time.time():
            self._data.pop(key, None)
            self.misses += 1
            return None
        entry.hits += 1
        self._data.move_to_end(key)
        self.hits += 1
        return entry.payload

    def put(self, qname: str, qtype: str, payload: bytes, ttl: int) -> None:
        ttl = max(self.ttl_floor, min(int(ttl or self.ttl_floor), self.ttl_ceiling))
        key = self._key(qname, qtype)
        self._data[key] = CacheEntry(payload, time.time() + ttl)
        self._data.move_to_end(key)
        while len(self._data) > self.max_entries:
            self._data.popitem(last=False)
            self.evictions += 1

    def purge_expired(self) -> int:
        now = time.time()
        stale = [k for k, v in self._data.items() if v.expires_at <= now]
        for k in stale:
            self._data.pop(k, None)
        return len(stale)

    def clear(self) -> None:
        self._data.clear()

    @property
    def stats(self) -> dict[str, float | int]:
        total = self.hits + self.misses
        return {
            "entries": len(self._data),
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "hit_rate": round(self.hits / total, 4) if total else 0.0,
        }
