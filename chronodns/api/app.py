"""
FastAPI dashboard + REST API.

Everything the page shows comes straight out of SQL — the same views and
window functions documented in sql/analytics/. The browser is a thin client;
the database does the analytics. That is the point of the project.

    GET  /                      the dashboard page
    GET  /api/health            liveness + backend info
    GET  /api/summary           KPI tiles
    GET  /api/timeline          per-minute event/block counts
    GET  /api/classes           threat class breakdown
    GET  /api/threats           highest-scoring recent events
    GET  /api/talkers           busiest source IPs
    GET  /api/tunnels           exfiltration leaderboard
    GET  /api/beacons           low-jitter beacon candidates
    GET  /api/alerts            open alerts
    GET  /api/model             model card + metrics
    POST /api/analyse           score an arbitrary domain on demand
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..config import get_config
from ..logging_utils import get_logger

log = get_logger("api")
UI_DIR = Path(__file__).resolve().parent.parent / "ui"


try:
    from pydantic import BaseModel

    class AnalyseRequest(BaseModel):
        """Body for POST /api/analyse.

        Defined at module scope on purpose: this module uses
        `from __future__ import annotations`, so FastAPI resolves type hints
        against the *module* namespace. A model defined inside create_app()
        would be invisible to that lookup and silently demoted to a query
        parameter.
        """

        domain: str
        qtype: str = "A"
        source_ip: str = "10.0.0.9"
except ImportError:                                        # pragma: no cover
    AnalyseRequest = None                                  # type: ignore[assignment]


def create_app():
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse

    from ..engine import ChronoEngine
    from ..storage import Repository, make_database
    from ..types import DNSQuery

    cfg = get_config()
    app = FastAPI(title="Chrono-DNS", version="1.0.0",
                  description="ML-driven DNS security gateway & threat intelligence engine")
    state: dict[str, Any] = {}

    @app.on_event("startup")
    async def _startup() -> None:
        db = make_database()
        await db.connect()
        repo = Repository(db)
        await repo.start()
        engine = ChronoEngine(cfg=cfg, repo=repo)
        engine.load_model()
        state.update(db=db, repo=repo, engine=engine)
        log.info("dashboard API ready")

    @app.on_event("shutdown")
    async def _shutdown() -> None:
        if "repo" in state:
            await state["repo"].close()
            await state["db"].close()

    # ------------------------------------------------------------------ #
    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        page = UI_DIR / "dashboard.html"
        html = page.read_text(encoding="utf-8")
        return html.replace("{{REFRESH_MS}}", str(cfg.api.refresh_ms))

    @app.get("/api/health")
    async def health() -> dict:
        engine = state["engine"]
        return {
            "status": "ok",
            "backend": "postgres" if cfg.database.is_postgres else "sqlite",
            "model": engine.model.version,
            "model_trained": engine.model.is_trained,
            "features": engine.extractor.count,
            "enforce": cfg.detection.enforce,
        }

    @app.get("/api/summary")
    async def summary(minutes: int = 1440) -> dict:
        s = await state["repo"].summary(minutes)
        return {k: (float(v) if isinstance(v, (int, float)) else v)
                for k, v in (s or {}).items()}

    @app.get("/api/timeline")
    async def timeline(minutes: int = 1440) -> list[dict]:
        rows = await state["repo"].timeline(minutes)
        return [{k: (str(v) if k == "bucket" else v) for k, v in r.items()}
                for r in rows]

    @app.get("/api/classes")
    async def classes(minutes: int = 1440) -> list[dict]:
        return await state["repo"].class_breakdown(minutes)

    @app.get("/api/threats")
    async def threats(limit: int = 25, minutes: int = 1440) -> list[dict]:
        rows = await state["repo"].top_threats(limit, minutes)
        return [{k: (str(v) if k == "ts" else v) for k, v in r.items()} for r in rows]

    @app.get("/api/talkers")
    async def talkers(limit: int = 15, minutes: int = 1440) -> list[dict]:
        return await state["repo"].top_talkers(limit, minutes)

    @app.get("/api/tunnels")
    async def tunnels(limit: int = 15, minutes: int = 1440) -> list[dict]:
        return await state["repo"].tunnel_candidates(limit, minutes)

    @app.get("/api/beacons")
    async def beacons(limit: int = 15) -> list[dict]:
        return await state["repo"].beacon_candidates(limit)

    @app.get("/api/alerts")
    async def alerts(limit: int = 25) -> list[dict]:
        return await state["repo"].open_alerts(limit)

    @app.get("/api/model")
    async def model_card() -> dict:
        card = Path(cfg.ml.model_dir) / "model_card.json"
        base = json.loads(card.read_text()) if card.exists() else {}
        engine = state["engine"]
        base["top_features"] = [
            {"name": n, "importance": round(v, 5)}
            for n, v in engine.model.global_importances(15)
        ]
        return base

    @app.post("/api/analyse")
    async def analyse(req: AnalyseRequest) -> dict:
        engine = state["engine"]
        detection = await engine.analyse(
            DNSQuery(qname=req.domain, qtype=req.qtype, source_ip=req.source_ip),
            persist=False)
        return {
            "domain": req.domain,
            "qtype": req.qtype,
            "verdict": detection.verdict.value,
            "threat_class": detection.threat_class.value,
            "score": round(detection.score, 4),
            "supervised": round(detection.supervised_score, 4),
            "anomaly": round(detection.anomaly_score, 4),
            "heuristic": round(detection.heuristic_score, 4),
            "latency_ms": round(detection.latency_ms, 3),
            "reasons": detection.reasons[:10],
            "top_features": [{"name": n, "contribution": round(c, 5)}
                             for n, c in detection.top_features],
            "features": {k: round(float(v), 5)
                         for k, v in list(detection.features.items())},
        }

    @app.get("/api/stats")
    async def stats() -> dict:
        return state["engine"].snapshot()

    return app


def run_dashboard(host: str | None = None, port: int | None = None) -> None:
    import uvicorn

    cfg = get_config()
    uvicorn.run(create_app(), host=host or cfg.api.host,
                port=port or cfg.api.port, log_level="warning")
