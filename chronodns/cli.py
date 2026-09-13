"""
Chrono-DNS command line interface.

    chronodns init          set up the database and seed threat intel
    chronodns dataset       generate a labelled synthetic capture
    chronodns train         train the RF + IsolationForest ensemble
    chronodns evade         adversarial (hard-mode) evaluation
    chronodns ablate        prove the model is not leaning on one shortcut
    chronodns replay        push a capture through the real inline pipeline
    chronodns live          animated SOC console over simulated live traffic
    chronodns serve         run the inline DNS gateway on port 5353
    chronodns dashboard     launch the web dashboard (FastAPI)
    chronodns explain       full feature breakdown for one domain
    chronodns hunt          run a threat-hunting SQL query
    chronodns report        SOC summary report from the database
    chronodns bench         throughput benchmark
    chronodns features      list every feature the extractor produces
    chronodns intel         manage local threat intelligence
    chronodns demo          run the entire pipeline end to end
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import sys
import time
from pathlib import Path

from . import BANNER, __version__
from .config import get_config
from .logging_utils import setup_logging

# --------------------------------------------------------------------------- #
# Rich is the whole reason the output looks good. Degrade gracefully if absent.
# --------------------------------------------------------------------------- #
try:
    from rich.box import ROUNDED, SIMPLE
    from rich.console import Console, Group
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.text import Text
    RICH = True
    console = Console()
except ImportError:                                        # pragma: no cover
    RICH = False
    console = None

VERDICT_STYLE = {
    "ALLOW": "green", "MONITOR": "cyan", "SUSPICIOUS": "yellow",
    "BLOCK": "bold red", "ERROR": "magenta",
}
CLASS_STYLE = {
    "benign": "green", "tunneling": "bold red", "dga": "bright_magenta",
    "c2_beacon": "bright_red", "unknown": "yellow",
}


def _print(*args, **kwargs) -> None:
    if RICH:
        console.print(*args, **kwargs)
    else:
        print(*args)


def banner() -> None:
    if RICH:
        console.print(Text(BANNER, style="bold cyan"))
        console.print(
            "  [dim]ML-driven detection of DNS tunnelling, DGA and C2 beaconing[/dim]\n")
    else:
        print(BANNER)


def sparkline(values: list[float], width: int = 40) -> str:
    blocks = "▁▂▃▄▅▆▇█"
    if not values:
        return ""
    vals = values[-width:]
    lo, hi = min(vals), max(vals)
    span = (hi - lo) or 1.0
    return "".join(blocks[min(int((v - lo) / span * (len(blocks) - 1)), 7)] for v in vals)


def bar(value: float, width: int = 24, ch: str = "█") -> str:
    filled = int(max(0.0, min(value, 1.0)) * width)
    return ch * filled + "·" * (width - filled)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
async def _open_stack(load_model: bool = True, init: bool = False):
    from .engine import ChronoEngine
    from .storage import Repository, init_schema, make_database

    cfg = get_config()
    db = make_database()
    await db.connect()
    if init:
        await init_schema(db)
    repo = Repository(db, cfg.database.batch_size, cfg.database.flush_interval)
    await repo.start()
    engine = ChronoEngine(cfg=cfg, repo=repo)
    if load_model:
        engine.load_model()
    return cfg, db, repo, engine


async def _close_stack(db, repo) -> None:
    await repo.close()
    await db.close()


def _table(title: str, columns: list[tuple[str, str]], rows: list[list],
           box_style=None) -> None:
    if not RICH:
        print(f"\n== {title} ==")
        print(" | ".join(c[0] for c in columns))
        for r in rows:
            print(" | ".join(str(x) for x in r))
        return
    t = Table(title=title, box=box_style or ROUNDED, header_style="bold cyan",
              title_style="bold white", expand=False)
    for name, style in columns:
        t.add_column(name, style=style, overflow="fold")
    for r in rows:
        t.add_row(*[str(x) for x in r])
    console.print(t)


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #
def cmd_init(args) -> int:
    async def run() -> int:
        from .storage import init_schema, make_database

        cfg = get_config()
        db = make_database()
        await db.connect()
        applied = await init_schema(db, seed=not args.no_seed, drop=args.reset)
        backend = "PostgreSQL" if cfg.database.is_postgres else "SQLite"
        location = (f"{cfg.database.host}:{cfg.database.port}/{cfg.database.database}"
                    if cfg.database.is_postgres else cfg.database.sqlite_path)
        counts = {}
        for table in ("threat_intel", "allowlist", "dns_events", "alerts"):
            try:
                counts[table] = await db.fetchval(f"SELECT COUNT(*) FROM {table}")
            except Exception:                              # noqa: BLE001
                counts[table] = "n/a"
        await db.close()

        _print(Panel.fit(
            f"[bold green]Database ready[/bold green]\n\n"
            f"backend    [cyan]{backend}[/cyan]\n"
            f"location   [dim]{location}[/dim]\n"
            f"migrations [cyan]{', '.join(applied)}[/cyan]\n\n"
            + "\n".join(f"{k:<14} [yellow]{v}[/yellow] rows" for k, v in counts.items()),
            title="chronodns init", border_style="green") if RICH else "database ready")
        return 0

    return asyncio.run(run())


def cmd_dataset(args) -> int:
    from .datagen import DatasetBuilder, ScenarioMix

    builder = DatasetBuilder(args.seed)
    mix = ScenarioMix()
    if args.scale != 1.0:
        for field_name in ("benign_hosts", "tunnel_hosts", "dga_hosts", "beacon_hosts"):
            setattr(mix, field_name, max(1, int(getattr(mix, field_name) * args.scale)))
    queries = builder.build(mix)
    if args.evasive:
        queries += builder.build_evasive(args.evasive)
        queries.sort(key=lambda q: q.timestamp)
    path = DatasetBuilder.write_csv(queries, args.out)
    stats = DatasetBuilder.stats(queries)

    _table("Synthetic capture", [("metric", "cyan"), ("value", "white")],
           [["file", str(path)],
            ["total queries", f"{stats['total']:,}"],
            ["hosts", stats["hosts"]],
            ["zones", f"{stats['zones']:,}"],
            ["span", f"{stats['span_seconds'] / 60:.1f} min"],
            ["rate", f"{stats['queries_per_second']} q/s"]])
    _table("Class distribution", [("label", "cyan"), ("count", "white"), ("share", "yellow")],
           [[k, f"{v:,}", f"{100 * v / stats['total']:.1f}%"]
            for k, v in sorted(stats["labels"].items(), key=lambda kv: -kv[1])])
    _table("Attack families", [("family", "cyan"), ("count", "white")],
           [[k, f"{v:,}"] for k, v in stats["families"].items()])
    return 0


def cmd_train(args) -> int:
    from .datagen import DatasetBuilder
    from .ml import train_model

    cfg = get_config()
    if args.data and Path(args.data).exists():
        queries = DatasetBuilder.read_csv(args.data)
        source = args.data
    else:
        builder = DatasetBuilder(args.seed)
        queries = builder.build()
        if args.harden:
            queries += DatasetBuilder(args.seed + 500).build_evasive(400)
            queries.sort(key=lambda q: q.timestamp)
        source = "generated in-memory" + (" (+ adversarial hardening)" if args.harden else "")

    _print(f"[dim]training on {len(queries):,} queries from {source}[/dim]"
           if RICH else f"training on {len(queries)} queries")

    exclude = tuple(args.ablate.split(",")) if args.ablate else ()
    model, report = train_model(queries, cfg,
                                report_path=Path(cfg.ml.model_dir) / "train_report.json",
                                exclude_prefixes=exclude)
    target = model.save(cfg.ml.model_dir)

    m = report["metrics"]
    _table("Model performance (held-out chronological split)",
           [("metric", "cyan"), ("value", "bold white"), ("", "dim")],
           [["accuracy", f"{m['accuracy']:.4f}", bar(m["accuracy"])],
            ["weighted F1", f"{m['f1']:.4f}", bar(m["f1"])],
            ["ROC-AUC (threat vs benign)", f"{m['roc_auc']:.4f}", bar(m["roc_auc"])],
            ["OOB score", f"{m['oob_score']:.4f}", bar(m["oob_score"])],
            ["detection rate @ block thr", f"{m['detection_rate']:.4f}", bar(m["detection_rate"])],
            ["false-positive rate", f"{m['false_positive_rate']:.5f}", bar(1 - m["false_positive_rate"])],
            ["train / test rows", f"{m['train_rows']:,} / {m['test_rows']:,}", ""],
            ["features", m["feature_count"], ""],
            ["train time", f"{m['train_seconds']}s", ""]])

    _table("Per-class results",
           [("class", "cyan"), ("precision", "white"), ("recall", "white"),
            ("f1", "yellow"), ("support", "dim")],
           [[k, f"{v['precision']:.4f}", f"{v['recall']:.4f}",
             f"{v['f1-score']:.4f}", int(v["support"])]
            for k, v in report["per_class"].items() if isinstance(v, dict)])

    _table("Top 15 discriminative features",
           [("#", "dim"), ("feature", "cyan"), ("importance", "white"), ("", "green")],
           [[i + 1, n, f"{v:.4f}", bar(v / report["top_features"][0][1], 20)]
            for i, (n, v) in enumerate(report["top_features"][:15])])

    labels = report["labels"]
    _table("Confusion matrix (rows = truth, cols = predicted)",
           [("", "bold cyan")] + [(name, "white") for name in labels],
           [[labels[i]] + row for i, row in enumerate(report["confusion_matrix"])])

    _print(f"\n[green]model saved[/green] -> [cyan]{target}[/cyan]  "
           f"version [yellow]{model.version}[/yellow]" if RICH else f"saved {target}")
    return 0


def cmd_evade(args) -> int:
    """The honesty command: how does the model do against an adversary?"""
    from .datagen import DatasetBuilder
    from .ml import ThreatEnsemble, evaluate_model

    cfg = get_config()
    model = ThreatEnsemble()
    if not model.load(cfg.ml.model_dir):
        _print("[red]no trained model — run `chronodns train` first[/red]")
        return 1

    evasive = DatasetBuilder(args.seed).build_evasive(args.count)
    result = evaluate_model(model, evasive)

    if RICH:
        console.print(Panel.fit(
            "[bold]Hard-mode evaluation[/bold]\n\n"
            "Standard synthetic attacks are loud: long labels, base32 payloads,\n"
            "NULL records, zero jitter. Every detector scores ~1.00 on them and\n"
            "the number tells you nothing.\n\n"
            "This set models an adversary who has read the detection logic:\n"
            "  [yellow]*[/yellow] tunnelling with short labels over A records at a slow rate\n"
            "  [yellow]*[/yellow] dictionary-word DGA with human-looking entropy\n"
            "  [yellow]*[/yellow] beacons with 35% jitter, well outside the metronome band\n",
            title="why this matters", border_style="yellow"))

    rows = []
    for thr in (0.45, 0.55, 0.70, 0.85):
        r = result[f"threshold_{thr}"]
        rows.append([f"{thr:.2f}", r["tp"], r["fp"], r["fn"], r["tn"],
                     f"{r['precision']:.4f}", f"{r['recall']:.4f}",
                     f"{r['fpr']:.5f}", bar(r["recall"], 18)])
    _table(f"Detection against evasive traffic (n={result['n']:,})",
           [("threshold", "cyan"), ("TP", "green"), ("FP", "red"), ("FN", "yellow"),
            ("TN", "dim"), ("precision", "white"), ("recall", "bold white"),
            ("FPR", "white"), ("", "green")], rows)
    _print(f"\nthreat-class accuracy: [bold]{result['class_accuracy']:.4f}[/bold]"
           if RICH else f"class accuracy {result['class_accuracy']}")
    _print("[dim]Tip: `chronodns train --harden` adds adversarial samples to the "
           "training mix and typically recovers most of the lost recall.[/dim]"
           if RICH else "")
    return 0


def cmd_ablate(args) -> int:
    """Retrain with whole feature families removed, to prove nothing is a crutch."""
    from .datagen import DatasetBuilder
    from .ml import train_model

    cfg = get_config()
    builder = DatasetBuilder(args.seed)
    queries = builder.build()

    groups = {
        "none (baseline)": (),
        "no TLD features": ("tld_", "is_numeric_tld"),
        "no temporal features": ("iat_", "beacon_", "zone_", "host_", "burstiness",
                                 "fano_factor", "time_entropy"),
        "no entropy features": ("shannon_", "normalized_entropy", "renyi_",
                                "min_entropy", "conditional_entropy", "entropy_"),
        "no n-gram features": ("bigram_", "trigram_", "unique_bigram", "unique_trigram",
                               "dictionary_hit_ratio"),
        "no structural features": ("qname_length", "label_", "max_label", "min_label",
                                   "mean_label", "std_label", "sub_label", "subdomain_",
                                   "at_label_limit", "near_name_limit", "long_label"),
    }
    rows = []
    for name, prefixes in groups.items():
        _, report = train_model(queries, cfg, exclude_prefixes=prefixes)
        m = report["metrics"]
        rows.append([name, m["ablated_features"], f"{m['accuracy']:.4f}",
                     f"{m['f1']:.4f}", f"{m['roc_auc']:.4f}",
                     f"{m['detection_rate']:.4f}", bar(m["f1"], 18)])

    _table("Feature-group ablation study",
           [("removed group", "cyan"), ("features off", "dim"), ("accuracy", "white"),
            ("F1", "bold white"), ("ROC-AUC", "white"), ("detect rate", "yellow"),
            ("", "green")], rows)
    _print("[dim]A small drop everywhere means the signal is genuinely distributed "
           "across the feature space, not carried by one lucky column.[/dim]"
           if RICH else "")
    return 0


def cmd_explain(args) -> int:
    async def run() -> int:
        from .types import DNSQuery

        cfg, db, repo, engine = await _open_stack()
        query = DNSQuery(qname=args.domain, qtype=args.qtype,
                         source_ip=args.source_ip, timestamp=time.time())
        detection = await engine.analyse(query, persist=False)
        f = detection.features

        if RICH:
            style = VERDICT_STYLE.get(detection.verdict.value, "white")
            console.print(Panel.fit(
                f"[bold]{args.domain}[/bold]  [dim]({args.qtype})[/dim]\n\n"
                f"verdict        [{style}]{detection.verdict.value}[/{style}]\n"
                f"threat class   [{CLASS_STYLE.get(detection.threat_class.value,'white')}]"
                f"{detection.threat_class.value}[/]\n"
                f"fused score    [bold]{detection.score:.4f}[/bold]  {bar(detection.score, 30)}\n"
                f"  supervised   {detection.supervised_score:.4f}  {bar(detection.supervised_score, 20)}\n"
                f"  anomaly      {detection.anomaly_score:.4f}  {bar(detection.anomaly_score, 20)}\n"
                f"  heuristic    {detection.heuristic_score:.4f}  {bar(detection.heuristic_score, 20)}\n"
                f"latency        {detection.latency_ms:.3f} ms",
                title="verdict", border_style=style.replace("bold ", "")))

        if detection.reasons:
            _table("Why", [("#", "dim"), ("reason", "yellow")],
                   [[i + 1, r] for i, r in enumerate(detection.reasons[:12])])

        if detection.top_features:
            _table("Most anomalous features",
                   [("feature", "cyan"), ("value", "white"),
                    ("contribution", "yellow"), ("", "red")],
                   [[n, f"{f.get(n, 0):.4f}", f"{c:.4f}", bar(min(c * 8, 1.0), 18)]
                    for n, c in detection.top_features])

        headline = ["shannon_entropy_full", "shannon_entropy_sub", "conditional_entropy",
                    "compression_ratio", "trigram_logprob", "vowel_consonant_ratio",
                    "dictionary_hit_ratio", "base32_conformance", "index_of_coincidence",
                    "qname_length", "max_label_length", "label_len_saturation",
                    "qtype_risk", "tld_risk", "subdomain_share"]
        _table("Key feature values",
               [("feature", "cyan"), ("value", "white")],
               [[n, f"{f.get(n, 0):.4f}"] for n in headline])

        if args.all:
            from .features import FEATURE_GROUPS
            for group, names in FEATURE_GROUPS.items():
                _table(f"All {group} features ({len(names)})",
                       [("feature", "cyan"), ("value", "white")],
                       [[n, f"{f.get(n, 0):.4f}"] for n in names])

        await _close_stack(db, repo)
        return 0

    return asyncio.run(run())


def cmd_replay(args) -> int:
    async def run() -> int:
        from .datagen import DatasetBuilder

        cfg, db, repo, engine = await _open_stack(init=True)
        if args.data and Path(args.data).exists():
            queries = DatasetBuilder.read_csv(args.data)
        else:
            queries = DatasetBuilder(args.seed).build()
        if args.limit:
            queries = queries[: args.limit]
        if args.fresh:
            await repo.purge_events()

        t0 = time.time()
        detections = []
        if RICH and not args.quiet:
            with Progress(SpinnerColumn(), TextColumn("[cyan]replaying capture"),
                          BarColumn(bar_width=40),
                          TextColumn("{task.completed:,}/{task.total:,}"),
                          TimeElapsedColumn(), console=console) as progress:
                task = progress.add_task("replay", total=len(queries))
                for q in queries:
                    detections.append(await engine.analyse(q))
                    progress.advance(task)
        else:
            for q in queries:
                detections.append(await engine.analyse(q))
        await repo.flush()
        elapsed = time.time() - t0

        blocked = [d for d in detections if d.verdict.is_blocked]
        susp = [d for d in detections if d.verdict.value == "SUSPICIOUS"]
        truth_bad = sum(1 for d in detections if (d.query.label or "benign") != "benign")
        caught = sum(1 for d in detections
                     if (d.query.label or "benign") != "benign"
                     and d.verdict.value in ("BLOCK", "SUSPICIOUS"))
        fp = sum(1 for d in detections
                 if (d.query.label or "benign") == "benign" and d.verdict.is_blocked)
        benign_total = len(detections) - truth_bad

        snap = engine.snapshot()
        _table("Replay result",
               [("metric", "cyan"), ("value", "bold white"), ("", "dim")],
               [["queries analysed", f"{len(detections):,}", ""],
                ["wall time", f"{elapsed:.2f}s", ""],
                ["throughput", f"{len(detections) / elapsed:,.0f} q/s", ""],
                ["p50 / p95 / p99 latency",
                 f"{snap['p50_ms']:.3f} / {snap['p95_ms']:.3f} / {snap['p99_ms']:.3f} ms", ""],
                ["blocked", f"{len(blocked):,}", bar(len(blocked) / max(len(detections), 1))],
                ["suspicious", f"{len(susp):,}", ""],
                ["true threats in capture", f"{truth_bad:,}", ""],
                ["threats caught", f"{caught:,}",
                 f"{100 * caught / max(truth_bad, 1):.2f}% recall"],
                ["false positives", f"{fp:,}",
                 f"{100 * fp / max(benign_total, 1):.4f}% of benign"],
                ["rows persisted", f"{repo.written:,}", ""]])

        breakdown = {}
        for d in detections:
            breakdown.setdefault(d.threat_class.value, [0, 0])
            breakdown[d.threat_class.value][0] += 1
            if d.verdict.is_blocked:
                breakdown[d.threat_class.value][1] += 1
        _table("Detected threat classes",
               [("class", "cyan"), ("detections", "white"), ("blocked", "red")],
               [[k, f"{v[0]:,}", f"{v[1]:,}"] for k, v in
                sorted(breakdown.items(), key=lambda kv: -kv[1][0])])

        worst = sorted(detections, key=lambda d: -d.score)[: args.top]
        _table(f"Top {args.top} detections",
               [("score", "bold red"), ("verdict", "white"), ("class", "magenta"),
                ("host", "dim"), ("query", "cyan"), ("why", "yellow")],
               [[f"{d.score:.3f}", d.verdict.value, d.threat_class.value,
                 d.query.source_ip, d.query.qname[:52],
                 (d.reasons[0][:46] if d.reasons else "")] for d in worst])

        await _close_stack(db, repo)
        return 0

    return asyncio.run(run())


def cmd_live(args) -> int:
    """Animated SOC console driven by a simulated live traffic stream."""
    if not RICH:
        print("`live` needs rich: pip install rich")
        return 1

    async def run() -> int:
        from .datagen import BeaconGenerator, BenignGenerator, DGAGenerator, TunnelGenerator
        from .types import DNSQuery

        cfg, db, repo, engine = await _open_stack(init=True)
        benign = BenignGenerator(args.seed)
        tunnel = TunnelGenerator(args.seed)
        dga = DGAGenerator(args.seed)
        beacon = BeaconGenerator(args.seed)
        rng = random.Random(args.seed)

        feed: list = []
        history: list[float] = []
        counters = {"ALLOW": 0, "MONITOR": 0, "SUSPICIOUS": 0, "BLOCK": 0}
        classes: dict[str, int] = {}
        start = time.time()
        beacon_clock = {"next": start + 4.0}

        def next_query() -> DNSQuery:
            now = time.time()
            r = rng.random()
            if now >= beacon_clock["next"]:
                beacon_clock["next"] = now + 6.0
                _ts, fqdn, qtype, _tool = beacon.session(
                    "c2.example", 1, now, interval=6.0, jitter_pct=0.03)[0]
                return DNSQuery(qname=fqdn, qtype=qtype,
                                source_ip="10.40.7.13", timestamp=now, label="c2_beacon")
            if r < 0.70:
                qn, qt = benign.query()
                return DNSQuery(qname=qn, qtype=qt, timestamp=now,
                                source_ip=f"10.10.{rng.randrange(1,9)}.{rng.randrange(2,250)}",
                                label="benign")
            if r < 0.86:
                qn, qt, _tool = tunnel.query(rng.choice(["iodine", "dnscat2", "dns2tcp"]))
                return DNSQuery(qname=qn, qtype=qt, source_ip="10.20.4.88",
                                timestamp=now, label="tunneling")
            qn, fam = dga.generate()
            return DNSQuery(qname=qn, qtype="A", source_ip="10.30.2.41",
                            timestamp=now, label="dga", family=fam)

        def render() -> Layout:
            layout = Layout()
            layout.split_column(
                Layout(name="head", size=8),
                Layout(name="body"),
                Layout(name="foot", size=9),
            )
            elapsed = max(time.time() - start, 1e-6)
            total = sum(counters.values())
            snap = engine.snapshot()

            head = Table.grid(expand=True)
            head.add_column(justify="left")
            head.add_column(justify="right")
            head.add_row(
                Text.from_markup(
                    f"[bold cyan]CHRONO-DNS[/bold cyan] [dim]v{__version__}[/dim]  "
                    f"[dim]model[/dim] [yellow]{snap['model']}[/yellow]  "
                    f"[dim]features[/dim] [yellow]{snap['features']}[/yellow]"),
                Text.from_markup(
                    f"[dim]uptime[/dim] {elapsed:6.1f}s   "
                    f"[dim]rate[/dim] [bold]{total/elapsed:5.1f}[/bold] q/s   "
                    f"[dim]p95[/dim] {snap['p95_ms']:.2f} ms"))
            counts = Table.grid(expand=True, padding=(0, 2))
            for _ in range(4):
                counts.add_column(justify="center")
            counts.add_row(
                Text.from_markup(f"[green]ALLOW[/green]\n[bold green]{counters['ALLOW']}[/bold green]"),
                Text.from_markup(f"[cyan]MONITOR[/cyan]\n[bold cyan]{counters['MONITOR']}[/bold cyan]"),
                Text.from_markup(f"[yellow]SUSPICIOUS[/yellow]\n[bold yellow]{counters['SUSPICIOUS']}[/bold yellow]"),
                Text.from_markup(f"[red]BLOCKED[/red]\n[bold red]{counters['BLOCK']}[/bold red]"))
            spark = sparkline(history, 58)
            layout["head"].update(Panel(
                Group(head, Text(""), counts, Text(""),
                      Text.from_markup(f"[dim]threat score[/dim] [magenta]{spark}[/magenta]")),
                border_style="cyan", title="live gateway"))

            stream = Table(box=SIMPLE, expand=True, header_style="bold dim")
            stream.add_column("time", style="dim", width=8)
            stream.add_column("verdict", width=11)
            stream.add_column("score", width=6, justify="right")
            stream.add_column("class", width=11)
            stream.add_column("source", style="dim", width=14)
            stream.add_column("query", overflow="ellipsis")
            for d in feed[-18:][::-1]:
                v = d.verdict.value
                stream.add_row(
                    time.strftime("%H:%M:%S", time.localtime(d.query.timestamp)),
                    Text(v, style=VERDICT_STYLE[v]),
                    f"{d.score:.3f}",
                    Text(d.threat_class.value, style=CLASS_STYLE.get(d.threat_class.value, "white")),
                    d.query.source_ip,
                    Text(d.query.qname[:70],
                         style="red" if d.verdict.is_blocked else "white"))
            layout["body"].update(Panel(stream, border_style="blue",
                                        title="query stream"))

            foot = Table.grid(expand=True, padding=(0, 3))
            foot.add_column(ratio=1)
            foot.add_column(ratio=1)
            cls_tbl = Table(box=SIMPLE, expand=True, header_style="bold dim")
            cls_tbl.add_column("threat class")
            cls_tbl.add_column("count", justify="right")
            cls_tbl.add_column("", ratio=1)
            for name, n in sorted(classes.items(), key=lambda kv: -kv[1])[:5]:
                cls_tbl.add_row(Text(name, style=CLASS_STYLE.get(name, "white")), str(n),
                                bar(n / max(total, 1), 16))
            recent = [d for d in feed if d.verdict.is_blocked][-5:][::-1]
            blk = Table(box=SIMPLE, expand=True, header_style="bold dim")
            blk.add_column("blocked")
            blk.add_column("reason", ratio=2, overflow="ellipsis")
            for d in recent:
                blk.add_row(Text(d.query.qname[:30], style="red"),
                            (d.reasons[0][:60] if d.reasons else ""))
            foot.add_row(cls_tbl, blk)
            layout["foot"].update(Panel(foot, border_style="magenta",
                                        title="rollup  ·  ctrl-c to stop"))
            return layout

        deadline = time.time() + args.duration
        with Live(render(), console=console, refresh_per_second=8,
                  screen=False) as live:
            try:
                while time.time() < deadline:
                    d = await engine.analyse(next_query())
                    feed.append(d)
                    if len(feed) > 400:
                        del feed[:200]
                    counters[d.verdict.value] = counters.get(d.verdict.value, 0) + 1
                    classes[d.threat_class.value] = classes.get(d.threat_class.value, 0) + 1
                    history.append(d.score)
                    if len(history) > 200:
                        del history[:100]
                    live.update(render())
                    await asyncio.sleep(max(args.interval, 0.001))
            except KeyboardInterrupt:
                pass

        await repo.flush()
        _print(f"\n[green]session complete[/green] — "
               f"{sum(counters.values()):,} queries, "
               f"[red]{counters['BLOCK']:,} blocked[/red], "
               f"{repo.written:,} rows written to the database")
        await _close_stack(db, repo)
        return 0

    return asyncio.run(run())


def cmd_serve(args) -> int:
    async def run() -> int:
        from .gateway import ChronoGateway

        cfg, db, repo, engine = await _open_stack(init=True)
        if args.monitor_only:
            cfg.detection.enforce = False
        if args.port:
            cfg.gateway.listen_port = args.port

        recent: list = []

        def on_detection(d) -> None:
            recent.append(d)
            if len(recent) > 200:
                del recent[:100]
            if RICH and d.verdict.value in ("BLOCK", "SUSPICIOUS"):
                style = VERDICT_STYLE[d.verdict.value]
                console.print(
                    f"[{style}]{d.verdict.value:<10}[/{style}] "
                    f"[bold]{d.score:.3f}[/bold] "
                    f"[magenta]{d.threat_class.value:<10}[/magenta] "
                    f"[dim]{d.query.source_ip:<15}[/dim] {d.query.qname[:60]}  "
                    f"[yellow]{d.reasons[0][:60] if d.reasons else ''}[/yellow]")

        gateway = ChronoGateway(engine, cfg, on_detection=on_detection)
        await gateway.start()

        if RICH:
            console.print(Panel.fit(
                f"[bold green]Chrono-DNS gateway listening[/bold green]\n\n"
                f"address    [cyan]{cfg.gateway.listen_host}:{cfg.gateway.listen_port}[/cyan] (UDP+TCP)\n"
                f"upstream   [cyan]{', '.join(cfg.gateway.upstream)}[/cyan]\n"
                f"model      [yellow]{engine.model.version}[/yellow]\n"
                f"mode       [{'red' if cfg.detection.enforce else 'yellow'}]"
                f"{'ENFORCING' if cfg.detection.enforce else 'MONITOR ONLY'}[/]\n\n"
                f"[dim]test it:[/dim]\n"
                f"  dig @{cfg.gateway.listen_host} -p {cfg.gateway.listen_port} github.com\n"
                f"  dig @{cfg.gateway.listen_host} -p {cfg.gateway.listen_port} "
                f"TXT mzxw6ytb.tunnel.example",
                title="serve", border_style="green"))

        try:
            while True:
                await asyncio.sleep(args.stats_interval)
                snap = gateway.snapshot()
                await repo.record_stats(
                    snap["gateway"]["queries"], snap["gateway"]["blocked"],
                    snap["gateway"]["suspicious"], snap["gateway"]["cache_hits"],
                    engine.latencies[-500:])
                if RICH and args.verbose:
                    console.print(f"[dim]{json.dumps(snap['gateway'])}[/dim]")
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            await gateway.stop()
            await _close_stack(db, repo)
        return 0

    try:
        return asyncio.run(run())
    except KeyboardInterrupt:
        _print("\n[yellow]gateway stopped[/yellow]")
        return 0


def cmd_bench(args) -> int:
    async def run() -> int:
        from .datagen import DatasetBuilder

        cfg, db, repo, engine = await _open_stack()
        queries = DatasetBuilder(args.seed).build()[: args.count]

        # 1. feature extraction only
        t0 = time.perf_counter()
        matrix, feats = engine.extractor.batch(queries)
        t_feat = time.perf_counter() - t0

        # 2. scoring only
        t0 = time.perf_counter()
        engine.model.score_batch(matrix, feats)
        t_score = time.perf_counter() - t0

        # 3. full inline path incl. policy (no DB)
        t0 = time.perf_counter()
        engine.analyse_batch_fast(queries)
        t_full = time.perf_counter() - t0

        # 4. true async path incl. DB write-behind
        t0 = time.perf_counter()
        for q in queries[: min(len(queries), 3000)]:
            await engine.analyse(q)
        await repo.flush()
        t_async = time.perf_counter() - t0
        n_async = min(len(queries), 3000)

        rows = [
            [f"feature extraction ({engine.extractor.count} features)", f"{t_feat:.3f}",
             f"{len(queries)/t_feat:,.0f}", f"{1000*t_feat/len(queries):.4f}"],
            ["ensemble scoring (RF + iForest)", f"{t_score:.3f}",
             f"{len(queries)/t_score:,.0f}", f"{1000*t_score/len(queries):.4f}"],
            ["full pipeline (batched)", f"{t_full:.3f}",
             f"{len(queries)/t_full:,.0f}", f"{1000*t_full/len(queries):.4f}"],
            ["full pipeline + DB (async, per-query)", f"{t_async:.3f}",
             f"{n_async/t_async:,.0f}", f"{1000*t_async/n_async:.4f}"],
        ]
        _table(f"Throughput benchmark (n={len(queries):,})",
               [("stage", "cyan"), ("seconds", "white"), ("queries/sec", "bold green"),
                ("ms/query", "yellow")], rows)
        _print("[dim]Reference: a busy enterprise recursive resolver sees "
               "2,000-20,000 q/s. Anything above that here means the detection "
               "layer is not the bottleneck — the network is.[/dim]" if RICH else "")
        await _close_stack(db, repo)
        return 0

    return asyncio.run(run())


def cmd_report(args) -> int:
    async def run() -> int:
        cfg, db, repo, engine = await _open_stack(load_model=False)
        minutes = args.minutes

        s = await repo.summary(minutes)
        if not s or not s.get("events"):
            _print("[yellow]no events in the window — run `chronodns replay` first[/yellow]")
            await _close_stack(db, repo)
            return 0

        _table(f"SOC summary — {'all recorded events' if minutes <= 0 else f'last {minutes} minutes'}",
               [("metric", "cyan"), ("value", "bold white")],
               [["events", f"{s['events']:,}"],
                ["blocked", f"{s['blocked']:,}"],
                ["distinct hosts", s["hosts"]],
                ["distinct zones", f"{s['zones']:,}"],
                ["mean threat score", f"{float(s['avg_score']):.4f}"],
                ["peak threat score", f"{float(s['max_score']):.4f}"],
                ["mean analysis latency", f"{float(s['avg_latency']):.3f} ms"]])

        _table("Threat class breakdown",
               [("class", "cyan"), ("events", "white"), ("blocked", "red"),
                ("avg score", "yellow")],
               [[r["threat_class"], f"{r['n']:,}", r["blocked"], r["avg_score"]]
                for r in await repo.class_breakdown(minutes)])

        _table("Top talkers",
               [("source", "cyan"), ("queries", "white"), ("zones", "white"),
                ("blocked", "red"), ("avg score", "yellow"), ("max", "yellow")],
               [[r["source_ip"], f"{r['queries']:,}", r["zones"], r["blocked"],
                 r["avg_score"], r["max_score"]]
                for r in await repo.top_talkers(10, minutes)])

        _table("Exfiltration leaderboard (zones by uploaded subdomain bytes)",
               [("zone", "cyan"), ("queries", "white"), ("unique subs", "white"),
                ("bytes up", "bold red"), ("avg sub entropy", "yellow"),
                ("hosts", "dim")],
               [[r["registrable"], f"{r['queries']:,}", f"{r['unique_subs']:,}",
                 f"{r['bytes_uploaded']:,}", r["avg_sub_entropy"], r["hosts"]]
                for r in await repo.tunnel_candidates(10, minutes)])

        _table("Top detections",
               [("score", "bold red"), ("class", "magenta"), ("verdict", "white"),
                ("host", "dim"), ("query", "cyan")],
               [[r["score"], r["threat_class"], r["verdict"], r["source_ip"],
                 r["qname"][:56]] for r in await repo.top_threats(12, minutes)])

        alerts = await repo.open_alerts(10)
        if alerts:
            _table("Open alerts",
                   [("sev", "bold red"), ("host", "cyan"), ("zone", "white"),
                    ("class", "magenta"), ("hits", "yellow"), ("max score", "white"),
                    ("bytes", "dim")],
                   [[a["severity"], a["source_ip"], a["registrable"],
                     a["threat_class"], a["hit_count"], a["max_score"],
                     a["bytes_exfil"]] for a in alerts])

        if args.json:
            payload = {
                "summary": {k: (float(v) if isinstance(v, (int, float)) else v)
                            for k, v in s.items()},
                "classes": await repo.class_breakdown(minutes),
                "top_talkers": await repo.top_talkers(10, minutes),
                "tunnels": await repo.tunnel_candidates(10, minutes),
            }
            Path(args.json).write_text(json.dumps(payload, indent=2, default=str))
            _print(f"[green]JSON report written to {args.json}[/green]")

        await _close_stack(db, repo)
        return 0

    return asyncio.run(run())


def cmd_hunt(args) -> int:
    async def run() -> int:
        cfg, db, repo, engine = await _open_stack(load_model=False)
        name = args.query

        if name == "tunnels":
            rows = await repo.tunnel_candidates(args.limit, args.minutes)
            _table("Tunnel candidates",
                   [("zone", "cyan"), ("queries", "white"), ("unique subs", "white"),
                    ("bytes up", "bold red"), ("entropy", "yellow"), ("hosts", "dim"),
                    ("peak", "magenta")],
                   [[r["registrable"], r["queries"], r["unique_subs"],
                     r["bytes_uploaded"], r["avg_sub_entropy"], r["hosts"],
                     r["peak_score"]] for r in rows])
        elif name == "beacons":
            rows = await repo.beacon_candidates(args.limit)
            cols = list(rows[0].keys()) if rows else []
            _table("Beacon candidates (lowest jitter first)",
                   [(c, "cyan" if i == 0 else "white") for i, c in enumerate(cols)],
                   [[r[c] for c in cols] for r in rows])
        elif name == "talkers":
            rows = await repo.top_talkers(args.limit, args.minutes)
            _table("Top talkers",
                   [("source", "cyan"), ("queries", "white"), ("zones", "white"),
                    ("blocked", "red"), ("avg", "yellow"), ("max", "yellow")],
                   [[r["source_ip"], r["queries"], r["zones"], r["blocked"],
                     r["avg_score"], r["max_score"]] for r in rows])
        elif name == "threats":
            rows = await repo.top_threats(args.limit, args.minutes)
            _table("Highest scoring events",
                   [("score", "bold red"), ("class", "magenta"), ("verdict", "white"),
                    ("host", "dim"), ("query", "cyan"), ("why", "yellow")],
                   [[r["score"], r["threat_class"], r["verdict"], r["source_ip"],
                     r["qname"][:48], (r["reasons"] or "")[:44]] for r in rows])
        elif name == "alerts":
            rows = await repo.open_alerts(args.limit)
            _table("Open alerts",
                   [("sev", "bold red"), ("host", "cyan"), ("zone", "white"),
                    ("class", "magenta"), ("hits", "yellow"), ("score", "white")],
                   [[r["severity"], r["source_ip"], r["registrable"],
                     r["threat_class"], r["hit_count"], r["max_score"]] for r in rows])
        elif name == "host":
            rows = await repo.host_velocity(args.value or "10.20.4.88", args.limit)
            _table(f"Timeline for {args.value}",
                   [("ts", "dim"), ("query", "cyan"), ("score", "bold white"),
                    ("ma10", "yellow"), ("gap s", "white"), ("class", "magenta"),
                    ("verdict", "white")],
                   [[time.strftime('%H:%M:%S', time.localtime(float(r['ts'])))
                     if not cfg.database.is_postgres else str(r["ts"])[11:19],
                     r["qname"][:46], r["score"], r["score_ma10"], r["gap_s"],
                     r["threat_class"], r["verdict"]] for r in rows])
        elif name == "search":
            rows = await repo.search(args.value or "", args.limit)
            _table(f"Search: *{args.value}*",
                   [("ts", "dim"), ("host", "cyan"), ("query", "white"),
                    ("score", "yellow"), ("verdict", "magenta")],
                   [[str(r["ts"])[:19], r["source_ip"], r["qname"][:52],
                     r["score"], r["verdict"]] for r in rows])
        else:
            _print("[red]unknown hunt[/red]: choose tunnels|beacons|talkers|threats|alerts|host|search")

        await _close_stack(db, repo)
        return 0

    return asyncio.run(run())


def cmd_features(args) -> int:
    from .features import FEATURE_COUNT, FEATURE_GROUPS, iter_feature_docs

    groups: dict[str, list] = {}
    for group, name, doc in iter_feature_docs():
        groups.setdefault(group, []).append((name, doc))

    for group, items in groups.items():
        _table(f"{group.title()} features ({len(items)})",
               [("#", "dim"), ("feature", "cyan"), ("what it measures", "white")],
               [[i + 1, n, d] for i, (n, d) in enumerate(items)])
    _print(f"\n[bold]{FEATURE_COUNT}[/bold] features total  "
           + "  ".join(f"[cyan]{g}[/cyan] {len(v)}" for g, v in FEATURE_GROUPS.items())
           if RICH else f"{FEATURE_COUNT} features")
    return 0


def cmd_intel(args) -> int:
    async def run() -> int:
        cfg, db, repo, engine = await _open_stack(load_model=False)
        if args.action == "add":
            await repo.add_intel(args.indicator, args.type, args.category,
                                 args.severity, "manual", args.note or "")
            _print(f"[green]added[/green] {args.indicator} "
                   f"({args.type}/{args.category}, severity {args.severity})")
        elif args.action == "allow":
            await repo.add_allowlist(args.indicator, "suffix", args.note or "")
            _print(f"[green]allowlisted[/green] {args.indicator}")
        elif args.action == "import":
            path = Path(args.indicator)
            added = 0
            for line in path.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = [p.strip() for p in line.split(",")]
                await repo.add_intel(parts[0],
                                     parts[1] if len(parts) > 1 else "zone",
                                     parts[2] if len(parts) > 2 else "malware",
                                     int(parts[3]) if len(parts) > 3 else 7,
                                     "import")
                added += 1
            _print(f"[green]imported {added} indicators[/green] from {path}")
        else:
            rows = await db.fetch(
                "SELECT indicator, ioc_type, category, severity, source FROM threat_intel "
                "ORDER BY severity DESC, indicator LIMIT ?", args.limit)
            _table("Local threat intelligence",
                   [("indicator", "cyan"), ("type", "white"), ("category", "magenta"),
                    ("sev", "bold red"), ("source", "dim")],
                   [[r["indicator"], r["ioc_type"], r["category"], r["severity"],
                     r["source"]] for r in rows])
            allow = await db.fetch("SELECT pattern, match_type, reason FROM allowlist "
                                   "ORDER BY pattern LIMIT ?", args.limit)
            _table("Allowlist",
                   [("pattern", "green"), ("match", "white"), ("reason", "dim")],
                   [[r["pattern"], r["match_type"], r["reason"] or ""] for r in allow])
        await _close_stack(db, repo)
        return 0

    return asyncio.run(run())


def cmd_dashboard(args) -> int:
    from .api.app import run_dashboard

    cfg = get_config()
    host = args.host or cfg.api.host
    port = args.port or cfg.api.port
    if RICH:
        console.print(Panel.fit(
            f"[bold green]Chrono-DNS dashboard[/bold green]\n\n"
            f"open [cyan]http://{host}:{port}[/cyan] in your browser\n"
            f"[dim]live SQL-backed SOC view — refreshes every "
            f"{cfg.api.refresh_ms} ms[/dim]",
            border_style="green"))
    run_dashboard(host, port)
    return 0


def cmd_demo(args) -> int:
    """One command that shows the entire project working."""
    banner()
    steps = [
        ("initialise database + seed threat intel", lambda: cmd_init(
            argparse.Namespace(no_seed=False, reset=True))),
        ("generate labelled synthetic capture", lambda: cmd_dataset(
            argparse.Namespace(seed=1337, scale=1.0, evasive=0,
                               out="data/capture.csv"))),
        ("train the ML ensemble", lambda: cmd_train(
            argparse.Namespace(seed=1337, data=None, harden=True, ablate=None))),
        ("replay the capture through the inline pipeline", lambda: cmd_replay(
            argparse.Namespace(seed=1337, data="data/capture.csv", limit=None,
                               fresh=True, top=12, quiet=False))),
        ("adversarial hard-mode evaluation", lambda: cmd_evade(
            argparse.Namespace(seed=99, count=250))),
        ("SOC report straight out of SQL", lambda: cmd_report(
            argparse.Namespace(minutes=0, json=None))),
        ("threat hunt: beacon detection via window functions", lambda: cmd_hunt(
            argparse.Namespace(query="beacons", limit=8, minutes=0, value=None))),
    ]
    for i, (title, fn) in enumerate(steps, 1):
        if RICH:
            console.rule(f"[bold cyan]STEP {i}/{len(steps)}[/bold cyan]  {title}")
        else:
            print(f"\n===== STEP {i}: {title} =====")
        rc = fn()
        if rc != 0:
            return rc
    if RICH:
        console.rule("[bold green]demo complete[/bold green]")
        console.print(
            "\nNext:  [cyan]chronodns live[/cyan]        animated SOC console\n"
            "       [cyan]chronodns serve[/cyan]       run the real DNS gateway\n"
            "       [cyan]chronodns dashboard[/cyan]   web UI at :8088\n")
    return 0


# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="chronodns",
        description="Chrono-DNS — ML-driven DNS security gateway & threat intelligence engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--version", action="version", version=f"chronodns {__version__}")
    p.add_argument("--log-level", default=None, help="DEBUG|INFO|WARNING|ERROR")
    p.add_argument("--quiet-log", action="store_true", help="suppress console logging")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("init", help="create schema and seed threat intel")
    s.add_argument("--reset", action="store_true", help="drop everything first")
    s.add_argument("--no-seed", action="store_true")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("dataset", help="generate a labelled synthetic capture")
    s.add_argument("--out", default="data/capture.csv")
    s.add_argument("--seed", type=int, default=1337)
    s.add_argument("--scale", type=float, default=1.0)
    s.add_argument("--evasive", type=int, default=0,
                   help="also append N evasive samples per class")
    s.set_defaults(func=cmd_dataset)

    s = sub.add_parser("train", help="train the ensemble")
    s.add_argument("--data", default=None, help="CSV capture (default: generate)")
    s.add_argument("--seed", type=int, default=1337)
    s.add_argument("--harden", action="store_true",
                   help="mix adversarial samples into training")
    s.add_argument("--ablate", default=None,
                   help="comma-separated feature prefixes to suppress")
    s.set_defaults(func=cmd_train)

    s = sub.add_parser("evade", help="adversarial hard-mode evaluation")
    s.add_argument("--count", type=int, default=300)
    s.add_argument("--seed", type=int, default=99)
    s.set_defaults(func=cmd_evade)

    s = sub.add_parser("ablate", help="feature-group ablation study")
    s.add_argument("--seed", type=int, default=1337)
    s.set_defaults(func=cmd_ablate)

    s = sub.add_parser("explain", help="full feature breakdown for one domain")
    s.add_argument("domain")
    s.add_argument("--qtype", default="A")
    s.add_argument("--source-ip", default="10.0.0.9")
    s.add_argument("--all", action="store_true", help="print all 102 features")
    s.set_defaults(func=cmd_explain)

    s = sub.add_parser("replay", help="replay a capture through the inline pipeline")
    s.add_argument("--data", default="data/capture.csv")
    s.add_argument("--seed", type=int, default=1337)
    s.add_argument("--limit", type=int, default=None)
    s.add_argument("--top", type=int, default=15)
    s.add_argument("--fresh", action="store_true", help="clear previous events first")
    s.add_argument("--quiet", action="store_true")
    s.set_defaults(func=cmd_replay)

    s = sub.add_parser("live", help="animated SOC console")
    s.add_argument("--duration", type=float, default=45.0)
    s.add_argument("--interval", type=float, default=0.18)
    s.add_argument("--seed", type=int, default=1337)
    s.set_defaults(func=cmd_live)

    s = sub.add_parser("serve", help="run the inline DNS gateway")
    s.add_argument("--port", type=int, default=None)
    s.add_argument("--monitor-only", action="store_true")
    s.add_argument("--stats-interval", type=float, default=15.0)
    s.add_argument("--verbose", action="store_true")
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("dashboard", help="launch the web dashboard")
    s.add_argument("--host", default=None)
    s.add_argument("--port", type=int, default=None)
    s.set_defaults(func=cmd_dashboard)

    s = sub.add_parser("bench", help="throughput benchmark")
    s.add_argument("--count", type=int, default=8000)
    s.add_argument("--seed", type=int, default=1337)
    s.set_defaults(func=cmd_bench)

    s = sub.add_parser("report", help="SOC report from the database")
    s.add_argument("--minutes", type=int, default=0,
                   help="window in minutes; 0 (default) = everything on record")
    s.add_argument("--json", default=None, help="also write a JSON report here")
    s.set_defaults(func=cmd_report)

    s = sub.add_parser("hunt", help="run a threat-hunting query")
    s.add_argument("query", choices=["tunnels", "beacons", "talkers", "threats",
                                     "alerts", "host", "search"])
    s.add_argument("value", nargs="?", default=None)
    s.add_argument("--limit", type=int, default=15)
    s.add_argument("--minutes", type=int, default=0,
                   help="window in minutes; 0 (default) = everything on record")
    s.set_defaults(func=cmd_hunt)

    s = sub.add_parser("features", help="list every extracted feature")
    s.set_defaults(func=cmd_features)

    s = sub.add_parser("intel", help="manage local threat intelligence")
    s.add_argument("action", choices=["list", "add", "allow", "import"],
                   default="list", nargs="?")
    s.add_argument("indicator", nargs="?", default=None)
    s.add_argument("--type", default="zone", choices=["domain", "zone", "tld", "ip"])
    s.add_argument("--category", default="malware")
    s.add_argument("--severity", type=int, default=8)
    s.add_argument("--note", default=None)
    s.add_argument("--limit", type=int, default=40)
    s.set_defaults(func=cmd_intel)

    s = sub.add_parser("demo", help="run the entire pipeline end to end")
    s.set_defaults(func=cmd_demo)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    cfg = get_config()
    setup_logging(args.log_level or cfg.log_level, cfg.log_file,
                  quiet=args.quiet_log)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        _print("\n[yellow]interrupted[/yellow]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
