"""Engine, session factory, and declarative base.

The connection URL comes from ``ODINEYES_DATABASE_URL`` (default: a local
sqlite file). JSON columns use ``JSONB`` on Postgres and portable ``JSON``
elsewhere, so the same models run against sqlite in tests.
"""

from __future__ import annotations

import os
import platform
import re
import sys
from threading import Lock
from contextlib import contextmanager
from typing import Iterator, Optional

from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.types import JSON


def _default_sqlite_url() -> str:
    """Pick a SQLite path that avoids cross-filesystem I/O errors.

    When running under WSL with the project on /mnt/c (the Windows mount),
    SQLite's file-locking breaks because the Windows FS driver doesn't support
    POSIX locks. We detect this and redirect the DB to a native Linux home dir.
    """
    if sys.platform == "linux":
        try:
            release = platform.uname().release.lower()
            if "microsoft" in release or "wsl" in release:
                wsl_dir = os.path.expanduser("~/.odineyes")
                os.makedirs(wsl_dir, exist_ok=True)
                db_path = os.path.join(wsl_dir, "odineyes.db")
                return f"sqlite:///{db_path}"
        except Exception:
            pass
    return "sqlite:///odineyes.db"


DEFAULT_URL = _default_sqlite_url()

# JSONB on Postgres (indexable, typed), plain JSON on sqlite/others.
JSONType = JSON().with_variant(JSONB(), "postgresql")


class Base(DeclarativeBase):
    pass


_engines: dict[str, Engine] = {}
_sessionmakers: dict[str, sessionmaker] = {}
_engine_lock = Lock()
_active_url: Optional[str] = None


def _resolve_url(url: Optional[str]) -> str:
    if url is not None:
        return url
    # Preserve the historical "init explicit DB, then session_scope()" contract
    # for repository/CLI callers. Once selected, the active store wins over a
    # later environment mutation; an explicit URL can intentionally reselect it.
    return _active_url or os.environ.get("ODINEYES_DATABASE_URL") or DEFAULT_URL


def get_engine(url: Optional[str] = None) -> Engine:
    """Return one process-wide engine per resolved database URL.

    The previous single mutable engine was rebound whenever a service supplied
    an explicit URL. Concurrent account workers could consequently create and
    use different session factories for the same scan. A keyed, locked cache
    makes engine/session selection stable across threads and test databases.
    """
    global _active_url
    resolved = _resolve_url(url)
    with _engine_lock:
        if resolved not in _engines:
            # sqlite: allow cross-thread use (the parallel fleet orchestrator),
            # and give writers time to wait for a concurrent scan transaction.
            connect_args = {"check_same_thread": False, "timeout": 30} if resolved.startswith("sqlite") else {}
            engine = create_engine(resolved, future=True, pool_pre_ping=True, connect_args=connect_args)
            if resolved.startswith("sqlite"):
                # SQLite ignores foreign keys unless enabled on every connection.
                # WAL lets dashboard reads continue during a scan write, while
                # busy_timeout absorbs short write-contention bursts.
                from sqlalchemy import event

                @event.listens_for(engine, "connect")
                def _sqlite_pragmas(dbapi_conn, _rec):  # noqa: ANN001
                    cur = dbapi_conn.cursor()
                    cur.execute("PRAGMA foreign_keys=ON")
                    cur.execute("PRAGMA busy_timeout=30000")
                    if ":memory:" not in resolved:
                        cur.execute("PRAGMA journal_mode=WAL")
                        cur.execute("PRAGMA synchronous=NORMAL")
                    cur.close()

            _engines[resolved] = engine
            _sessionmakers[resolved] = sessionmaker(
                bind=engine, expire_on_commit=False, future=True,
            )
        if url is not None:
            _active_url = resolved
        return _engines[resolved]


def get_sessionmaker(url: Optional[str] = None) -> sessionmaker:
    resolved = _resolve_url(url)
    get_engine(resolved if url is not None else None)
    return _sessionmakers[resolved]


def init_db(url: Optional[str] = None) -> Engine:
    """Create all tables. MVP uses ``create_all``; migrations (alembic) come
    once the schema stabilises. Columns added to existing tables after a DB was
    first created are patched in with ADD COLUMN (create_all never alters)."""
    from sqlalchemy import inspect, text

    from odineyes.db import models  # noqa: F401 — register mappers

    engine = get_engine(url)
    Base.metadata.create_all(engine)

    # (table, column, DDL) — additive-only, both sqlite and Postgres support it.
    patches = [
        ("assets", "risk_score", "ALTER TABLE assets ADD COLUMN risk_score FLOAT NOT NULL DEFAULT 0"),
        ("issues", "actively_exploited", "ALTER TABLE issues ADD COLUMN actively_exploited BOOLEAN NOT NULL DEFAULT 0"),
        ("issues", "exploit_count", "ALTER TABLE issues ADD COLUMN exploit_count INTEGER NOT NULL DEFAULT 0"),
        ("issues", "last_exploit_at", "ALTER TABLE issues ADD COLUMN last_exploit_at TIMESTAMP"),
        ("issues", "historically_exploited", "ALTER TABLE issues ADD COLUMN historically_exploited BOOLEAN NOT NULL DEFAULT 0"),
        ("issues", "first_exploit_at", "ALTER TABLE issues ADD COLUMN first_exploit_at TIMESTAMP"),
        ("vulnerabilities", "epss", "ALTER TABLE vulnerabilities ADD COLUMN epss FLOAT"),
        ("vulnerabilities", "epss_percentile", "ALTER TABLE vulnerabilities ADD COLUMN epss_percentile FLOAT"),
        ("vulnerabilities", "kev", "ALTER TABLE vulnerabilities ADD COLUMN kev BOOLEAN NOT NULL DEFAULT 0"),
        ("compliance_snapshots", "origin", "ALTER TABLE compliance_snapshots ADD COLUMN origin VARCHAR(32)"),
        ("runtime_events", "count", "ALTER TABLE runtime_events ADD COLUMN count INTEGER NOT NULL DEFAULT 1"),
        ("issues", "confidence", "ALTER TABLE issues ADD COLUMN confidence FLOAT NOT NULL DEFAULT 1.0"),
        ("issues", "evidence_status", "ALTER TABLE issues ADD COLUMN evidence_status VARCHAR(16) NOT NULL DEFAULT 'confirmed'"),
        ("cloud_accounts", "external_id", "ALTER TABLE cloud_accounts ADD COLUMN external_id VARCHAR(64)"),
        ("cloud_accounts", "disk_scan_role_arn", "ALTER TABLE cloud_accounts ADD COLUMN disk_scan_role_arn VARCHAR(512)"),
        ("cloud_accounts", "realtime_role_arn", "ALTER TABLE cloud_accounts ADD COLUMN realtime_role_arn VARCHAR(512)"),
        ("cloud_accounts", "api_key", "ALTER TABLE cloud_accounts ADD COLUMN api_key VARCHAR(64)"),
        ("cloud_accounts", "api_secret", "ALTER TABLE cloud_accounts ADD COLUMN api_secret VARCHAR(128)"),
        ("cloud_accounts", "onboarding_token_hash", "ALTER TABLE cloud_accounts ADD COLUMN onboarding_token_hash VARCHAR(64)"),
        ("cloud_accounts", "onboarding_token_expires_at", "ALTER TABLE cloud_accounts ADD COLUMN onboarding_token_expires_at TIMESTAMP"),
        ("cloud_accounts", "onboarding_token_used_at", "ALTER TABLE cloud_accounts ADD COLUMN onboarding_token_used_at TIMESTAMP"),
        ("cloud_accounts", "onboarding_status", "ALTER TABLE cloud_accounts ADD COLUMN onboarding_status VARCHAR(32) NOT NULL DEFAULT 'connected'"),
        ("cloud_accounts", "last_verified_at", "ALTER TABLE cloud_accounts ADD COLUMN last_verified_at TIMESTAMP"),
        ("cloud_accounts", "excluded_regions", "ALTER TABLE cloud_accounts ADD COLUMN excluded_regions TEXT NOT NULL DEFAULT '[]'"),
        ("cloud_accounts", "last_verify_status", "ALTER TABLE cloud_accounts ADD COLUMN last_verify_status VARCHAR(32)"),
        ("assets", "last_seen_scan_id", "ALTER TABLE assets ADD COLUMN last_seen_scan_id INTEGER REFERENCES scan_jobs(id)"),
        ("findings", "asset_id", "ALTER TABLE findings ADD COLUMN asset_id INTEGER REFERENCES assets(id)"),
        ("findings", "suppressed_by", "ALTER TABLE findings ADD COLUMN suppressed_by VARCHAR(32)"),
        ("findings", "suppressed_why", "ALTER TABLE findings ADD COLUMN suppressed_why TEXT"),
        ("issues", "entry_asset_id", "ALTER TABLE issues ADD COLUMN entry_asset_id INTEGER REFERENCES assets(id)"),
        ("issues", "evidence", "ALTER TABLE issues ADD COLUMN evidence JSON NOT NULL DEFAULT '[]'"),
        ("vulnerabilities", "asset_id", "ALTER TABLE vulnerabilities ADD COLUMN asset_id INTEGER REFERENCES assets(id)"),
        ("vulnerabilities", "scanner_source", "ALTER TABLE vulnerabilities ADD COLUMN scanner_source VARCHAR(32) NOT NULL DEFAULT 'ssm-osv'"),
        ("vulnerabilities", "package_type", "ALTER TABLE vulnerabilities ADD COLUMN package_type VARCHAR(64)"),
        ("vulnerabilities", "target", "ALTER TABLE vulnerabilities ADD COLUMN target VARCHAR(1024)"),
        ("vulnerabilities", "package_path", "ALTER TABLE vulnerabilities ADD COLUMN package_path VARCHAR(1024)"),
        ("dspm_findings", "asset_id", "ALTER TABLE dspm_findings ADD COLUMN asset_id INTEGER REFERENCES assets(id)"),
    ]
    inspector = inspect(engine)
    for table, column, ddl in patches:
        if table in inspector.get_table_names():
            existing = {c["name"] for c in inspector.get_columns(table)}
            if column not in existing:
                with engine.begin() as conn:
                    conn.execute(text(ddl))

    _migrate_asset_natural_key(engine)
    _backfill_cspm_links(engine)

    # create_all does not add indexes to tables that already exist. Keep the
    # model's query indexes additive and idempotent for upgraded installations.
    for table in Base.metadata.sorted_tables:
        for index in table.indexes:
            index.create(engine, checkfirst=True)
    return engine


def _backfill_cspm_links(engine: Engine) -> None:
    """Link legacy evidence to canonical assets without guessing identity.

    Older databases stored resource ids in JSON/text evidence only.  The new
    nullable FKs are populated when there is one unambiguous asset match; rows
    that cannot be proven are intentionally left NULL instead of being linked
    to the wrong cloud resource.  Attack-path hop rows are reconstructed from
    the already persisted ordered JSON path once.
    """
    from sqlalchemy import select

    from odineyes.db.models import Asset, DspmFinding, Finding, Issue, IssueHop, Vulnerability

    def key(value: str | None) -> str:
        if not value:
            return ""
        part = value.split("://", 1)[-1].split(":")[-1].split("/")[-1]
        return part.lower()

    with Session(engine, future=True) as session:
        assets = list(session.execute(select(Asset)).scalars())
        by_resource = {(a.account_id, a.resource_id): a for a in assets}
        by_store_key: dict[tuple[int, str], list[Asset]] = {}
        for asset in assets:
            by_store_key.setdefault((asset.account_id, key(asset.resource_id)), []).append(asset)

        for finding in session.execute(select(Finding).where(Finding.asset_id.is_(None))).scalars():
            asset = by_resource.get((finding.account_id, finding.resource_id))
            if asset is not None:
                finding.asset_id = asset.id

        for vuln in session.execute(select(Vulnerability).where(Vulnerability.asset_id.is_(None))).scalars():
            asset = by_resource.get((vuln.account_id, vuln.resource_id))
            if asset is not None:
                vuln.asset_id = asset.id

        for classification in session.execute(select(DspmFinding).where(DspmFinding.asset_id.is_(None))).scalars():
            direct = by_resource.get((classification.account_id, classification.store_id))
            candidates = [direct] if direct is not None else by_store_key.get(
                (classification.account_id, key(classification.store_id)), []
            )
            if len(candidates) == 1:
                classification.asset_id = candidates[0].id

        for issue in session.execute(select(Issue)).scalars():
            if issue.entry_asset_id is None:
                asset = by_resource.get((issue.account_id, issue.resource_id))
                if asset is not None:
                    issue.entry_asset_id = asset.id
            if issue.hops:
                continue
            for order, hop in enumerate(issue.path or []):
                if not isinstance(hop, dict) or not hop.get("id"):
                    continue
                node_id = str(hop["id"])
                asset = by_resource.get((issue.account_id, node_id))
                session.add(IssueHop(
                    issue_id=issue.id,
                    asset_id=asset.id if asset is not None else None,
                    hop_order=order,
                    node_id=node_id,
                    node_kind=str(hop.get("kind") or "") or None,
                    label=str(hop.get("name") or hop.get("label") or "") or None,
                    evidence={"source": "legacy_issue_path"},
                ))
        session.commit()


def _migrate_asset_natural_key(engine: Engine) -> None:
    """Tenant-scope the asset key without discarding existing inventory.

    Earlier releases enforced UNIQUE(resource_id, cloud_provider), which lets
    one account collide with another. PostgreSQL can replace the constraint in
    place. SQLite requires a transactional table rebuild because it cannot drop
    a table constraint; IDs are preserved so asset_events foreign keys remain
    valid after the replacement table is renamed.
    """
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    if "assets" not in inspector.get_table_names():
        return
    constraints = inspector.get_unique_constraints("assets")
    current = next(
        (c for c in constraints if c.get("name") == "uq_asset_natural_key"),
        None,
    )
    expected = ["account_id", "cloud_provider", "resource_id"]
    if current and current.get("column_names") == expected:
        return
    if current is None:
        # An unmanaged schema is safer to stop than to guess at its identity
        # constraints and possibly merge tenant data.
        raise RuntimeError("assets table is missing uq_asset_natural_key")

    if engine.dialect.name == "postgresql":
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE assets DROP CONSTRAINT uq_asset_natural_key"))
            conn.execute(text(
                "ALTER TABLE assets ADD CONSTRAINT uq_asset_natural_key "
                "UNIQUE (account_id, cloud_provider, resource_id)"
            ))
        return

    if engine.dialect.name != "sqlite":
        raise RuntimeError(
            "asset natural-key migration is supported for SQLite and PostgreSQL only"
        )

    replacement = "assets__tenant_key_migration"
    with engine.connect() as conn:
        create_sql = conn.execute(text(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='assets'"
        )).scalar_one()
        migrated_sql = re.sub(
            r"CONSTRAINT\s+uq_asset_natural_key\s+UNIQUE\s*\([^)]*\)",
            "CONSTRAINT uq_asset_natural_key UNIQUE (account_id, cloud_provider, resource_id)",
            create_sql,
            count=1,
            flags=re.IGNORECASE,
        ).replace("CREATE TABLE assets", f"CREATE TABLE {replacement}", 1)
        if migrated_sql == create_sql or "UNIQUE (account_id, cloud_provider, resource_id)" not in migrated_sql:
            raise RuntimeError("could not rewrite SQLite asset natural-key constraint")

        columns = [column["name"] for column in inspect(conn).get_columns("assets")]
        quoted = ", ".join(f'"{column}"' for column in columns)

        # PRAGMA foreign_keys cannot change inside a transaction.
        conn.exec_driver_sql("PRAGMA foreign_keys=OFF")
        conn.commit()
        try:
            with conn.begin():
                conn.execute(text(f"DROP TABLE IF EXISTS {replacement}"))
                conn.execute(text(migrated_sql))
                conn.execute(text(
                    f"INSERT INTO {replacement} ({quoted}) SELECT {quoted} FROM assets"
                ))
                conn.execute(text("DROP TABLE assets"))
                conn.execute(text(f"ALTER TABLE {replacement} RENAME TO assets"))
        finally:
            conn.exec_driver_sql("PRAGMA foreign_keys=ON")
            conn.commit()


def reset_db(url: Optional[str] = None) -> Engine:
    """Drop every table and recreate a clean schema. Destructive — callers must
    gate this behind an explicit fresh-start decision (see server.py lifespan);
    never call it against a database you want to keep."""
    from odineyes.db import models  # noqa: F401 — register mappers

    engine = get_engine(url)
    Base.metadata.drop_all(engine)
    return init_db(url)


@contextmanager
def session_scope(url: Optional[str] = None) -> Iterator[Session]:
    """Transactional scope: commit on success, roll back on error, always close."""
    factory = get_sessionmaker(url)
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
