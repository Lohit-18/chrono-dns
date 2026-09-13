"""
Upstream forwarding with failover.

Chrono-DNS is a *forwarding* resolver: it makes the security decision and then
hands the question to a real recursive resolver (Cloudflare, Quad9, Google —
all free). Multiple upstreams are tried in order, so one flaky resolver does
not take the gateway down with it.
"""

from __future__ import annotations

import asyncio
import functools
import struct
import time

from ..logging_utils import get_logger

log = get_logger("gateway.resolver")


class _UpstreamProtocol(asyncio.DatagramProtocol):
    def __init__(self, future: asyncio.Future) -> None:
        self.future = future

    def datagram_received(self, data: bytes, addr) -> None:
        if not self.future.done():
            self.future.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self.future.done():
            self.future.set_exception(exc)


class UpstreamResolver:
    def __init__(self, servers: list[str], port: int = 53, timeout: float = 2.5) -> None:
        self.servers = servers or ["1.1.1.1"]
        self.port = port
        self.timeout = timeout
        self.failures: dict[str, int] = dict.fromkeys(self.servers, 0)
        self.queries = 0
        self.errors = 0
        self.latencies: list[float] = []

    # ------------------------------------------------------------------ #
    async def query_udp(self, payload: bytes) -> bytes | None:
        """Forward a raw DNS packet over UDP, trying each upstream in turn."""
        loop = asyncio.get_running_loop()
        order = sorted(self.servers, key=lambda s: self.failures.get(s, 0))
        for server in order:
            t0 = time.perf_counter()
            future: asyncio.Future = loop.create_future()
            transport = None
            try:
                transport, _ = await loop.create_datagram_endpoint(
                    functools.partial(_UpstreamProtocol, future),
                    remote_addr=(server, self.port),
                )
                transport.sendto(payload)
                data = await asyncio.wait_for(future, timeout=self.timeout)
                self.queries += 1
                self.latencies.append((time.perf_counter() - t0) * 1000)
                if len(self.latencies) > 5000:
                    self.latencies = self.latencies[-2500:]
                self.failures[server] = max(0, self.failures.get(server, 0) - 1)
                return data
            except (asyncio.TimeoutError, OSError) as exc:
                self.failures[server] = self.failures.get(server, 0) + 1
                self.errors += 1
                log.debug("upstream %s failed: %s", server, exc)
            finally:
                if transport:
                    transport.close()
        return None

    async def query_tcp(self, payload: bytes) -> bytes | None:
        """TCP forwarding — needed for large answers and tunnelling over TCP/53."""
        for server in self.servers:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(server, self.port), timeout=self.timeout)
                writer.write(struct.pack("!H", len(payload)) + payload)
                await writer.drain()
                header = await asyncio.wait_for(reader.readexactly(2), self.timeout)
                (length,) = struct.unpack("!H", header)
                body = await asyncio.wait_for(reader.readexactly(length), self.timeout)
                writer.close()
                self.queries += 1
                return body
            except Exception as exc:                       # noqa: BLE001
                self.errors += 1
                log.debug("tcp upstream %s failed: %s", server, exc)
        return None

    @property
    def stats(self) -> dict:
        lat = sorted(self.latencies) or [0.0]
        return {
            "queries": self.queries,
            "errors": self.errors,
            "servers": self.servers,
            "failures": dict(self.failures),
            "p50_ms": round(lat[len(lat) // 2], 2),
            "p95_ms": round(lat[min(int(len(lat) * 0.95), len(lat) - 1)], 2),
        }
