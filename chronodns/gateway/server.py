"""
The inline DNS gateway.

An asyncio UDP + TCP DNS proxy built on `dnslib`. Every question is parsed,
analysed by the ChronoEngine, and then either forwarded upstream or answered
with a sinkhole record.

Operational notes that matter:

* **Analysis is on the hot path, persistence is not.** Scoring takes ~0.1 ms;
  the database write is queued and flushed in the background by the repository.
* **Blocking returns an answer, not silence.** A dropped packet makes the
  client retry three times and then hang for seconds. Returning 0.0.0.0 (or
  NXDOMAIN) fails fast and shows up cleanly in the client's own logs.
* **Ports below 1024 need privileges.** The default listen port is 5353 so the
  whole project runs as an unprivileged user with no setcap games.
"""

from __future__ import annotations

import asyncio
import contextlib
import struct
import time
from collections.abc import Callable
from typing import Any

from ..config import Config, get_config
from ..engine import ChronoEngine
from ..logging_utils import get_logger
from ..types import DNSQuery, Verdict
from .cache import AnswerCache
from .resolver import UpstreamResolver

log = get_logger("gateway.server")

try:
    from dnslib import AAAA, QTYPE, RCODE, RR, A, DNSHeader, DNSRecord
    DNSLIB_AVAILABLE = True
except ImportError:                                       # pragma: no cover
    DNSLIB_AVAILABLE = False
    log.warning("dnslib not installed — gateway disabled, analysis still works")


class GatewayStats:
    def __init__(self) -> None:
        self.start = time.time()
        self.queries = 0
        self.blocked = 0
        self.suspicious = 0
        self.cache_hits = 0
        self.upstream_errors = 0
        self.malformed = 0

    def as_dict(self) -> dict[str, Any]:
        uptime = max(time.time() - self.start, 1e-6)
        return {
            "uptime_s": round(uptime, 1),
            "queries": self.queries,
            "qps": round(self.queries / uptime, 2),
            "blocked": self.blocked,
            "suspicious": self.suspicious,
            "cache_hits": self.cache_hits,
            "upstream_errors": self.upstream_errors,
            "malformed": self.malformed,
            "block_rate": round(self.blocked / self.queries, 4) if self.queries else 0.0,
        }


class DNSGatewayProtocol(asyncio.DatagramProtocol):
    """UDP listener. One instance handles the whole socket."""

    def __init__(self, gateway: ChronoGateway) -> None:
        self.gateway = gateway
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        asyncio.create_task(self._handle(data, addr))

    async def _handle(self, data: bytes, addr) -> None:
        try:
            response = await self.gateway.handle_packet(data, addr[0], addr[1], "udp")
            if response and self.transport:
                self.transport.sendto(response, addr)
        except Exception as exc:                          # noqa: BLE001
            log.error("udp handler error from %s: %s", addr, exc)


class ChronoGateway:
    """Ties the engine, the cache and the upstream resolver into a resolver."""

    def __init__(self, engine: ChronoEngine, cfg: Config | None = None,
                 on_detection: Callable | None = None) -> None:
        self.cfg = cfg or get_config()
        self.engine = engine
        self.cache = AnswerCache(self.cfg.gateway.cache_max_entries,
                                 self.cfg.gateway.cache_ttl_floor)
        self.upstream = UpstreamResolver(self.cfg.gateway.upstream,
                                         self.cfg.gateway.upstream_port,
                                         self.cfg.gateway.upstream_timeout)
        self.stats = GatewayStats()
        self.on_detection = on_detection
        self._udp_transport: Any = None
        self._tcp_server: Any = None
        self._semaphore = asyncio.Semaphore(self.cfg.gateway.max_concurrent)

    # ------------------------------------------------------------------ #
    async def handle_packet(self, data: bytes, src_ip: str, src_port: int,
                            transport: str) -> bytes | None:
        async with self._semaphore:
            return await self._handle_packet(data, src_ip, src_port, transport)

    async def _handle_packet(self, data: bytes, src_ip: str, src_port: int,
                             transport: str) -> bytes | None:
        if not DNSLIB_AVAILABLE:
            return None
        self.stats.queries += 1
        try:
            request = DNSRecord.parse(data)
        except Exception:                                  # noqa: BLE001
            self.stats.malformed += 1
            log.debug("malformed packet from %s", src_ip)
            return None

        if not request.questions:
            return None
        question = request.questions[0]
        qname = str(question.qname).rstrip(".").lower()
        qtype = QTYPE.get(question.qtype, str(question.qtype))

        query = DNSQuery(
            qname=qname, qtype=qtype, source_ip=src_ip, source_port=src_port,
            transport=transport, timestamp=time.time(), txid=request.header.id,
            payload_size=len(data),
        )

        detection = await self.engine.analyse(query)

        if self.on_detection:
            with contextlib.suppress(Exception):
                self.on_detection(detection)

        if detection.verdict is Verdict.BLOCK:
            self.stats.blocked += 1
            return self._sinkhole_response(request, question, qtype)
        if detection.verdict is Verdict.SUSPICIOUS:
            self.stats.suspicious += 1

        # --- cache lookup -------------------------------------------------
        cached = self.cache.get(qname, qtype)
        if cached is not None:
            self.stats.cache_hits += 1
            detection.cached = True
            return self._retag(cached, request.header.id)

        # --- forward upstream ---------------------------------------------
        upstream_reply = (await self.upstream.query_tcp(data) if transport == "tcp"
                          else await self.upstream.query_udp(data))
        if upstream_reply is None:
            self.stats.upstream_errors += 1
            return self._servfail(request)

        try:
            parsed = DNSRecord.parse(upstream_reply)
            ttl = min((rr.ttl for rr in parsed.rr), default=self.cfg.gateway.cache_ttl_floor)
            if parsed.header.rcode == RCODE.NOERROR and parsed.rr:
                self.cache.put(qname, qtype, upstream_reply, ttl)
        except Exception:                                  # noqa: BLE001
            pass
        return upstream_reply

    # ------------------------------------------------------------------ #
    def _sinkhole_response(self, request, question, qtype: str) -> bytes:
        """Answer a blocked query fast, with a record the client understands."""
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1),
                          q=request.q)
        if qtype == "A":
            reply.add_answer(RR(question.qname, QTYPE.A, ttl=60,
                                rdata=A(self.cfg.gateway.sinkhole_ip)))
        elif qtype == "AAAA":
            reply.add_answer(RR(question.qname, QTYPE.AAAA, ttl=60,
                                rdata=AAAA(self.cfg.gateway.sinkhole_ipv6)))
        else:
            # TXT / NULL / CNAME tunnels get NXDOMAIN — no channel at all.
            reply.header.rcode = RCODE.NXDOMAIN
        return reply.pack()

    @staticmethod
    def _servfail(request) -> bytes:
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, ra=1), q=request.q)
        reply.header.rcode = RCODE.SERVFAIL
        return reply.pack()

    @staticmethod
    def _retag(payload: bytes, txid: int) -> bytes:
        """Rewrite the transaction ID of a cached answer for the new client."""
        return struct.pack("!H", txid) + payload[2:]

    # ------------------------------------------------------------------ #
    async def start(self) -> None:
        if not DNSLIB_AVAILABLE:
            raise RuntimeError("dnslib is required to run the gateway: pip install dnslib")
        loop = asyncio.get_running_loop()
        host, port = self.cfg.gateway.listen_host, self.cfg.gateway.listen_port

        self._udp_transport, _ = await loop.create_datagram_endpoint(
            lambda: DNSGatewayProtocol(self), local_addr=(host, port))
        log.info("UDP listener bound to %s:%d", host, port)

        if self.cfg.gateway.enable_tcp:
            self._tcp_server = await asyncio.start_server(
                self._handle_tcp, host, port)
            log.info("TCP listener bound to %s:%d", host, port)

        log.info("upstream resolvers: %s", ", ".join(self.cfg.gateway.upstream))
        log.info("enforcement: %s", "ON" if self.cfg.detection.enforce else "MONITOR-ONLY")

    async def _handle_tcp(self, reader: asyncio.StreamReader,
                          writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
        try:
            header = await asyncio.wait_for(reader.readexactly(2), 5.0)
            (length,) = struct.unpack("!H", header)
            body = await asyncio.wait_for(reader.readexactly(length), 5.0)
            reply = await self.handle_packet(body, peer[0], peer[1], "tcp")
            if reply:
                writer.write(struct.pack("!H", len(reply)) + reply)
                await writer.drain()
        except Exception as exc:                          # noqa: BLE001
            log.debug("tcp session error: %s", exc)
        finally:
            writer.close()

    async def stop(self) -> None:
        if self._udp_transport:
            self._udp_transport.close()
        if self._tcp_server:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
        log.info("gateway stopped")

    def snapshot(self) -> dict[str, Any]:
        return {
            "gateway": self.stats.as_dict(),
            "cache": self.cache.stats,
            "upstream": self.upstream.stats,
            "engine": self.engine.snapshot(),
        }
