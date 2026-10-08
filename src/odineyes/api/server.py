from __future__ import annotations
import os
import io
import re
import time
import asyncio
import datetime
import logging
from collections import OrderedDict
from contextlib import asynccontextmanager
from fastapi import FastAPI, Header, HTTPException, Body, Depends
from fastapi.middleware.cors import CORSMiddleware

from odineyes.api.security import require_operator

logger = logging.getLogger(__name__)


def _fresh_start_enabled(db_url: str) -> bool:
    """Whether to wipe and rescan on this boot. Default ON for the local sqlite
    dev DB (fast iteration loop); default OFF for anything else (Postgres/prod)
    so a real deployment is never silently destroyed by a routine restart.
    ODINEYES_FRESH_START=true/false overrides either default explicitly."""
    override = os.environ.get("ODINEYES_FRESH_START")
    if override is not None:
        return override.strip().lower() in ("1", "true", "yes", "on")
    return False


def _scan_registered(region: str) -> dict:
    """Scan every registered account via cross-account assume-role. This is the
    only server-side scan path: it never scans the runner's own ambient identity
    (which must be a non-root IAM user whose sole job is to call AssumeRole).
    Blocking — call via asyncio.to_thread from async contexts."""
    from odineyes.inventory.orchestrator import MultiAccountOrchestrator
    results = MultiAccountOrchestrator(region=region).scan_all()
    return {
        "accounts": len(results),
        "completed": sum(r.status == "completed" for r in results),
        "failed": sum(r.status == "failed" for r in results),
        "results": [r.to_dict() for r in results],
    }


async def _startup_scan() -> None:
    """Fresh-start convenience: the DB was just reset, so scan every registered
    account immediately instead of waiting for the periodic monitor. Best-effort —
    no accounts / bad credentials must not crash server startup."""
    region = os.environ.get("ODINEYES_SCAN_REGION", "us-east-1")
    try:
        logger.info("Fresh start: scanning registered accounts (region=%s)...", region)
        result = await asyncio.to_thread(_scan_registered, region)
        logger.info("Fresh start: initial scan complete: %s", result)
    except Exception as e:  # noqa: BLE001 — must not crash startup
        logger.warning(f"Fresh-start scan failed: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Inventory persistence spine (Phase 1) — optional; needs the `db` extra.
    fresh = False
    try:
        from odineyes.db.base import DEFAULT_URL, init_db, reset_db
        db_url = os.environ.get("ODINEYES_DATABASE_URL", DEFAULT_URL)
        fresh = _fresh_start_enabled(db_url)
        if fresh:
            reset_db()
            logger.info("Fresh start: inventory store reset.")
        else:
            init_db()
            logger.info("Inventory store initialised.")
    except Exception as e:
        logger.warning(f"Inventory store unavailable (install '.[db]'): {e}")

    # Background monitors (both no-op unless their interval env is set):
    #   _compliance_monitor — re-scores compliance + snapshots drift
    #   _inventory_monitor  — full scan -> findings -> issues + webhook alerts
    compliance_task = asyncio.create_task(_compliance_monitor())
    scan_task = asyncio.create_task(_inventory_monitor())
    # One-shot: only after a fresh reset, so the UI isn't empty on boot.
    startup_scan_task = asyncio.create_task(_startup_scan()) if fresh else None

    yield

    tasks = [compliance_task, scan_task] + ([startup_scan_task] if startup_scan_task else [])
    for task in tasks:
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass

app = FastAPI(lifespan=lifespan)

_CORS_ORIGINS = [o.strip() for o in os.environ.get("ODINEYES_CORS_ORIGINS", "*").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# Inventory store router (Phase 1). Guarded so /api/live/* still works without
# the optional `db` extra installed.
try:
    from odineyes.api.inventory_routes import router as inventory_router
    app.include_router(inventory_router)
    
    from odineyes.api.autoconnect import router as autoconnect_router
    app.include_router(autoconnect_router)

    from odineyes.api.onboarding_routes import router as onboarding_router
    app.include_router(onboarding_router)

    from odineyes.api.realtime_routes import router as realtime_router
    app.include_router(realtime_router)
except Exception as e:
    logger.warning(f"Inventory routes not mounted: {e}")

# Product customization router (control overrides, custom frameworks/policies).
try:
    from odineyes.api.config_routes import router as config_router
    app.include_router(config_router)
except Exception as e:
    logger.warning(f"Config routes not mounted: {e}")

@app.get("/health")
def health():
    return {"status": "ok"}


# ── Live CSPM (misconfiguration + compliance, no Neo4j required) ─
# Runs the real boto3 ScanEngine against the account and returns config
# findings + per-framework compliance scores. Separate from /api/live/scan so
# the heavy check sweep never blocks the graph dashboard.

_cspm_cache: dict = {}          # key -> (epoch_seconds, result)
_CSPM_CACHE_MAX = 32
_CSPM_CACHE_TTL = 900           # seconds; steampipe sweeps take minutes — cache longer

# Input allow-lists — never pass unvalidated strings to boto3 / shell-adjacent paths.
_REGION_RE = re.compile(r"^[a-z]{2}-[a-z]+-\d{1,2}$")
_PROFILE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def _resolve_account(profile: str | None) -> str | None:
    """Best-effort account id via STS (read-only)."""
    try:
        import boto3
        return boto3.Session(profile_name=profile or "default") \
            .client("sts").get_caller_identity().get("Account")
    except Exception as e:
        logger.warning(f"CSPM: could not resolve account via STS: {e}")
        return None


def _run_cspm(region: str, profile: str | None, frameworks: list[str]) -> dict:
    """Compliance scores come from Steampipe's aws-compliance mod when the binary
    is present; otherwise fall back to the in-tree Python check engine. Both
    return the same shape the Compliance tab consumes."""
    from odineyes.core import steampipe_runner as sp
    if sp.available():
        try:
            return _run_cspm_steampipe(region, profile, frameworks)
        except Exception as e:
            logger.warning(
                "Steampipe compliance failed (%s); falling back to Python engine.", e,
                exc_info=True,
            )
    return _run_cspm_python(region, profile, frameworks)


def _run_cspm_steampipe(region: str, profile: str | None, frameworks: list[str]) -> dict:
    from odineyes.core import steampipe_runner as sp
    res = sp.run(frameworks, region, profile)
    compliance = res["compliance"]
    findings = res["findings"]
    if not compliance:
        raise RuntimeError("steampipe returned no scored frameworks")

    passing = sum(fw["passing"] for fw in compliance.values())
    total = sum(fw["total"] for fw in compliance.values())
    pass_rate = round(passing / total * 100, 1) if total else 0.0

    account = next((f["account"] for f in findings if f.get("account")), None) \
        or _resolve_account(profile)

    # ponytail: naive risk = inverse of pass rate; the Compliance tab doesn't
    # render risk and the attack-path risk lives on a different endpoint.
    return {
        "account": account,
        "region": region,
        "summary": {"pass_rate": pass_rate, "passing": passing,
                    "total": total, "failing": len(findings)},
        "risk_score": round(100 - pass_rate),
        "risk_level": ("low" if pass_rate >= 80 else "medium" if pass_rate >= 50 else "high"),
        "findings": findings,
        "compliance": compliance,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "engine": "steampipe",
    }


def _run_cspm_python(region: str, profile: str | None, frameworks: list[str]) -> dict:
    from odineyes.core.engine import ScanEngine
    from odineyes.core.compliance_mapper import ComplianceMapper
    from rich.console import Console

    # Force quiet + a throwaway console so the engine's rich tables never leak
    # to server stdout.
    sink = Console(file=io.StringIO(), force_terminal=False)
    engine = ScanEngine(
        providers=["aws"],
        regions=[region],
        profile=profile or "default",
        compliance_frameworks=frameworks,
        parallel=True,
        threads=10,
        console=sink,
    )
    results = engine.run(quiet=True)
    if not results:
        raise RuntimeError("No checks matched (engine returned empty result)")

    findings = results["findings"]
    compliance = ComplianceMapper().score(findings, frameworks)
    account = _resolve_account(profile)

    return {
        "account": account,
        "region": region,
        "summary": results["summary"],
        "risk_score": results["risk_score"],
        "risk_level": results["risk_level"],
        "findings": findings,
        "compliance": compliance,
        "generated_at": results["scan_metadata"]["end_time"],
        "engine": "python",
    }


@app.get("/api/live/cspm")
def live_cspm(region: str = "us-east-1", profile: str = None,
              frameworks: str = "CIS,SOC2,NIST,PCI-DSS,FSBP", refresh: bool = False):
    """Run the real CSPM check engine against the live AWS account.

    Returns misconfiguration findings + per-framework compliance scores.
    Requires AWS credentials (profile/env). No mock layer anywhere: on failure
    this returns 500 with ``detail`` and the frontend renders that error
    verbatim (ApiError reads ``response.detail``).
    """
    from odineyes.core.config_store import available_frameworks
    from odineyes.core import steampipe_runner as sp

    if not _REGION_RE.match(region):
        raise HTTPException(status_code=400, detail="Invalid region")
    if profile is not None and not _PROFILE_RE.match(profile):
        raise HTTPException(status_code=400, detail="Invalid profile")

    # Only accept known framework ids (built-in + custom + steampipe benchmarks);
    # cap to bound work.
    known = set(available_frameworks()) | set(sp.BENCHMARKS)
    fw = [f.strip() for f in frameworks.split(",") if f.strip() in known][:16]
    if not fw:
        raise HTTPException(status_code=400, detail="No valid frameworks requested")

    key = f"{region}:{profile}:{','.join(sorted(fw))}"
    cached = _cspm_cache.get(key)
    fresh = cached is not None and (time.time() - cached[0]) < _CSPM_CACHE_TTL
    if refresh or not fresh:
        try:
            result = _run_cspm(region, profile, fw)
        except Exception as e:
            # Log full detail server-side; return a generic message so internal
            # state / credentials info never leaks to the client.
            logger.error(f"CSPM scan failed: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail="CSPM scan failed")
        if len(_cspm_cache) >= _CSPM_CACHE_MAX:
            _cspm_cache.clear()
        _cspm_cache[key] = (time.time(), result)
    return _cspm_cache[key][1]


# ── continuous + dynamic compliance ─────────────────────────────
# Persist a per-framework snapshot (history/trend) and record control drift
# (pass<->fail transitions). Runs on demand (POST) and, if enabled, on a
# background interval. Reuses the live CSPM engine + its cache.

def _persist_compliance(result: dict) -> dict:
    from odineyes.db.base import session_scope
    from odineyes.inventory.repository import ComplianceRepository
    comp = result.get("compliance") or {}
    if not comp:
        return {"snapshots": 0, "drifts": 0}
    with session_scope() as session:
        return ComplianceRepository.snapshot(
            session, compliance=comp,
            account=result.get("account"), region=result.get("region"),
            origin=result.get("engine"),
        )


@app.post("/api/live/compliance/snapshot")
def compliance_snapshot(account_id: int | None = None, region: str = "us-east-1", profile: str = None,
                        frameworks: str = "CIS,SOC2,NIST,PCI-DSS", refresh: bool = False):
    """Run CSPM now and persist a compliance snapshot + drift. Manual trigger
    for the continuous-compliance store (the background monitor calls the same
    path on an interval). Reuses the CSPM cache unless refresh=true."""
    if account_id is not None:
        from odineyes.db.base import session_scope
        from odineyes.db.models import CloudAccount, Finding
        from odineyes.core.compliance_mapper import ComplianceMapper
        from odineyes.inventory.repository import ComplianceRepository
        from sqlalchemy import select

        with session_scope() as session:
            acct = session.get(CloudAccount, account_id)
            if not acct:
                raise HTTPException(status_code=404, detail="account not found")
            
            db_findings = session.execute(
                select(Finding).where(Finding.account_id == account_id)
            ).scalars().all()
            
            mapped_findings = [
                {
                    "check_id": f.rule_id,
                    "status": "FAIL" if f.status == "open" else "PASS",
                    "compliance_mappings": f.compliance or {}
                }
                for f in db_findings
            ]
            
            mapper = ComplianceMapper()
            fws = [f.strip() for f in frameworks.split(",") if f.strip()]
            comp = mapper.score(mapped_findings, fws)
            
            stats = ComplianceRepository.snapshot(
                session, compliance=comp,
                account=acct.account_identifier, region=region,
                origin="inventory"
            )
            return {"persisted": stats, "account": acct.account_identifier, "region": region}

    result = live_cspm(region=region, profile=profile, frameworks=frameworks, refresh=refresh)
    stats = _persist_compliance(result)
    return {"persisted": stats, "account": result.get("account"), "region": result.get("region")}


async def _compliance_monitor() -> None:
    """Background loop: re-score + snapshot every N minutes when
    ODINEYES_COMPLIANCE_INTERVAL_MIN > 0 (off by default — live CSPM costs
    AWS API calls). Region/profile/frameworks via env."""
    try:
        interval_min = float(os.environ.get("ODINEYES_COMPLIANCE_INTERVAL_MIN", "0") or 0)
    except ValueError:
        interval_min = 0
    if interval_min <= 0:
        logger.info("Continuous compliance disabled "
                    "(set ODINEYES_COMPLIANCE_INTERVAL_MIN>0 to enable).")
        return
    region = os.environ.get("ODINEYES_COMPLIANCE_REGION", "us-east-1")
    profile = os.environ.get("ODINEYES_COMPLIANCE_PROFILE") or None
    frameworks = os.environ.get("ODINEYES_COMPLIANCE_FRAMEWORKS", "CIS,SOC2,NIST,PCI-DSS")
    logger.info("Continuous compliance ON: every %.0f min (region=%s).", interval_min, region)
    while True:
        try:
            # Blocking boto3 scan → run off the event loop. refresh=True so each
            # cycle re-scans rather than serving a stale cache entry.
            result = await asyncio.to_thread(
                live_cspm, region=region, profile=profile, frameworks=frameworks, refresh=True)
            stats = await asyncio.to_thread(_persist_compliance, result)
            logger.info("compliance snapshot persisted: %s", stats)
        except Exception as e:  # noqa: BLE001 — a bad cycle must not kill the loop
            logger.error("compliance monitor cycle failed: %s", e)
        await asyncio.sleep(interval_min * 60)


# ── continuous scanning + alerting ──────────────────────────────
# Full inventory scan -> findings -> attack-path issues on an interval, with a
# webhook alert on findings that newly cross into open + critical/high. Off by
# default (live scans cost AWS API calls). Reuses inventory.monitor.run_cycle.

async def _inventory_monitor() -> None:
    """Background loop: a full scan cycle every N minutes when
    ODINEYES_SCAN_INTERVAL_MIN > 0. Region/profile via env; alerts via
    ODINEYES_ALERT_WEBHOOK."""
    try:
        interval_min = float(os.environ.get("ODINEYES_SCAN_INTERVAL_MIN", "0") or 0)
    except ValueError:
        interval_min = 0
    if interval_min <= 0:
        logger.info("Continuous scanning disabled "
                    "(set ODINEYES_SCAN_INTERVAL_MIN>0 to enable).")
        return
    region = os.environ.get("ODINEYES_SCAN_REGION", "us-east-1")
    logger.info("Continuous scanning ON: every %.0f min (region=%s).", interval_min, region)
    while True:
        try:
            result = await asyncio.to_thread(_scan_registered, region)
            logger.info("scan cycle persisted: %s", result)
        except Exception as e:  # noqa: BLE001 — a bad cycle must not kill the loop
            logger.error("scan monitor cycle failed: %s", e)
        await asyncio.sleep(interval_min * 60)


@app.post("/api/live/scan-cycle", dependencies=[Depends(require_operator)])
def scan_cycle(region: str = "us-east-1"):
    """Scan every registered account now (assume-role -> inventory -> findings ->
    issues). Manual trigger for the continuous-scanning loop. `region` is the STS
    home region; each account sweeps its enabled regions."""
    if not _REGION_RE.match(region):
        raise HTTPException(status_code=400, detail="Invalid region")
    try:
        return _scan_registered(region)
    except Exception as e:
        logger.error(f"scan cycle failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="scan cycle failed")


# --- eBPF Sensor Ingestion Pipeline ---
@app.post("/api/internal/runtime-events")
def ingest_runtime_events(event: dict = Body(...), x_tenant_id: str = Header(default="default")):
    """Receive enriched events from the eBPF sensor and persist them to the
    runtime_events store (read by the Threats page)."""
    from odineyes.db.base import session_scope
    from odineyes.inventory.repository import RuntimeEventRepository

    event_type = event.get("event_type") or "runtime_event"
    comm = event.get("comm", "")
    filename = event.get("filename", "")
    process = " ".join(p for p in (comm, filename) if p) or None

    # Canonical persistence — independent of Neo4j.
    exploited: list[int] = []
    with session_scope() as session:
        RuntimeEventRepository.record(
            session,
            event_type=event_type,
            severity=str(event.get("severity", "info")),
            resource_id=event.get("node") or event.get("instance_id"),
            workload=event.get("container"),
            process=process,
            pid=event.get("pid"),
            summary=event.get("summary"),
            raw=event,
        )
        # Step-4 correlation: if this event lands on a host that is a hop in an
        # open attack path, that path is being actively walked right now.
        try:
            from odineyes.inventory.exploitation import correlate_event
            exploited = correlate_event(session, {**event, "event_type": event_type})
        except Exception as e:  # noqa: BLE001 — correlation must not sink ingestion
            logger.warning(f"exploitation correlation failed: {e}")

    return {"status": "ingested", "type": event_type, "exploited_paths": exploited}


# Bounded idempotency cache for batch ingest. batch_id -> seen-at epoch. This is
# a dedup guard only (not data) so it can live in memory; oldest evicted first.
_seen_batches: "OrderedDict[str, float]" = OrderedDict()
_BATCH_DEDUP_MAX = 4096


@app.post("/api/internal/runtime-events/batch")
def ingest_runtime_events_batch(body: dict = Body(...), x_tenant_id: str = Header(default="default")):
    """Idempotent batch ingest from the eBPF sensor's detection engine.

    Body: {"host_id", "events": [...], "findings": [...], "batch_id", "batch_ts"}.
    Each event/finding is persisted via RuntimeEventRepository and run through the
    Step-4 exploitation correlation — identical to the single-event path, just
    amortised. A repeated batch_id is a no-op (sensor retries are safe)."""
    from odineyes.db.base import session_scope
    from odineyes.inventory.exploitation import correlate_event
    from odineyes.inventory.repository import RuntimeEventRepository

    batch_id = body.get("batch_id")
    if batch_id and batch_id in _seen_batches:
        return {"accepted": 0, "findings_created": 0, "exploited_paths": [], "duplicate": True}

    events = body.get("events") or []
    findings = body.get("findings") or []
    exploited: list[int] = []
    accepted = 0
    with session_scope() as session:
        for ev in [*events, *findings]:
            et = ev.get("event_type") or "runtime_event"
            comm, filename = ev.get("comm", ""), ev.get("filename", "")
            process = " ".join(p for p in (comm, filename) if p) or None
            RuntimeEventRepository.record(
                session,
                event_type=et,
                severity=str(ev.get("severity", "info")),
                resource_id=ev.get("node") or ev.get("instance_id") or body.get("host_id"),
                workload=ev.get("workload") or ev.get("container"),
                process=process,
                pid=ev.get("pid"),
                summary=ev.get("summary"),
                raw=ev,
            )
            accepted += 1
            try:
                exploited += correlate_event(session, {**ev, "event_type": et})
            except Exception as e:  # noqa: BLE001 — correlation must not sink ingest
                logger.warning(f"batch correlation failed: {e}")

    if batch_id:
        _seen_batches[batch_id] = time.time()
        while len(_seen_batches) > _BATCH_DEDUP_MAX:
            _seen_batches.popitem(last=False)
    return {
        "accepted": accepted,
        "findings_created": len(findings),
        "exploited_paths": sorted(set(exploited)),
    }
