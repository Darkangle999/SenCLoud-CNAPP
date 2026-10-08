"""init_db()'s additive-migration contract: a column added to a model must also
land in db/base.py's ``patches`` list, or every pre-existing database (anything
that isn't a brand-new install) breaks on first write to that column — while
tests that always start from a fresh create_all() never notice, since a new
table gets every mapped column natively.

Caught for real: CloudAccount.api_key/api_secret were added to the model
without a matching patch, so get_or_create() failed its own session.flush()
with "no such column" on any database created before those fields existed.
"""

from __future__ import annotations

import sqlite3

from odineyes.db.base import init_db, session_scope
from odineyes.inventory.repository import AccountRepository


def _pre_existing_db(path) -> str:
    """A cloud_accounts table shaped like it predates every patched-in column
    (external_id, api_key, api_secret) — the realistic "upgrade an existing
    install" case, not the "fresh install" case every other fixture exercises."""
    url = f"sqlite:///{path}"
    conn = sqlite3.connect(path)
    conn.execute("""CREATE TABLE cloud_accounts (
        id INTEGER PRIMARY KEY, provider VARCHAR(16) NOT NULL,
        account_identifier VARCHAR(128) NOT NULL, name VARCHAR(256),
        role_arn VARCHAR(512), is_active BOOLEAN NOT NULL DEFAULT 1,
        created_at DATETIME NOT NULL,
        UNIQUE(provider, account_identifier)
    )""")
    conn.execute(
        "INSERT INTO cloud_accounts (provider, account_identifier, is_active, created_at) "
        "VALUES ('aws', '123456789012', 1, datetime('now'))"
    )
    conn.commit()
    conn.close()
    return url


def test_init_db_patches_every_mapped_column_into_a_pre_existing_table(tmp_path):
    """Every column CloudAccount declares must exist on the table after
    init_db() — not just the ones some patch author remembered to add."""
    url = _pre_existing_db(tmp_path / "legacy.db")
    init_db(url)

    import sqlite3 as sq
    conn = sq.connect(tmp_path / "legacy.db")
    cols = {row[1] for row in conn.execute("PRAGMA table_info(cloud_accounts)")}
    conn.close()

    from odineyes.db.models import CloudAccount
    mapped_cols = {c.name for c in CloudAccount.__table__.columns}
    missing = mapped_cols - cols
    assert not missing, f"columns on the model but not patched into an existing DB: {missing}"


def test_preexisting_account_survives_the_upgrade(tmp_path):
    url = _pre_existing_db(tmp_path / "legacy.db")
    init_db(url)
    with session_scope(url) as s:
        acct = AccountRepository.get_or_create(s, "aws", "123456789012")
        assert acct.id is not None
        assert acct.api_key is None  # column exists now, just unset for the old row


def test_new_account_onboarding_works_against_an_upgraded_db(tmp_path):
    """The exact regression: onboarding a *new* account failed too, since the
    failing flush happened in get_or_create() before any api_key was even set."""
    url = _pre_existing_db(tmp_path / "legacy2.db")
    init_db(url)
    with session_scope(url) as s:
        acct = AccountRepository.get_or_create(s, "aws", "441586174413", "krizna")
        acct.api_key = "test-key"
        acct.api_secret = "test-secret"
        assert acct.external_id.startswith("cs-")
    with session_scope(url) as s:
        acct = AccountRepository.get_or_create(s, "aws", "441586174413")
        assert acct.api_key == "test-key"


def test_legacy_vulnerability_table_gets_trivy_evidence_columns(tmp_path):
    path = tmp_path / "legacy-vulns.db"
    url = _pre_existing_db(path)
    conn = sqlite3.connect(path)
    conn.execute("""CREATE TABLE vulnerabilities (
        id INTEGER PRIMARY KEY,
        account_id INTEGER NOT NULL,
        asset_id INTEGER,
        resource_id VARCHAR(1024) NOT NULL,
        cve_id VARCHAR(64) NOT NULL,
        package VARCHAR(256) NOT NULL,
        installed_version VARCHAR(128),
        severity VARCHAR(16) NOT NULL DEFAULT 'unknown',
        cvss FLOAT,
        summary TEXT,
        fixed_version VARCHAR(128),
        epss FLOAT,
        epss_percentile FLOAT,
        kev BOOLEAN NOT NULL DEFAULT 0,
        status VARCHAR(16) NOT NULL DEFAULT 'open',
        first_seen_at DATETIME NOT NULL,
        last_seen_at DATETIME NOT NULL,
        resolved_at DATETIME
    )""")
    conn.commit()
    conn.close()

    init_db(url)

    conn = sqlite3.connect(path)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(vulnerabilities)")}
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    conn.close()

    assert {"scanner_source", "package_type", "target", "package_path"} <= columns
    assert "security_scan_runs" in tables


def test_legacy_findings_table_gets_suppression_evidence_columns(tmp_path):
    path = tmp_path / "legacy-findings.db"
    url = _pre_existing_db(path)
    conn = sqlite3.connect(path)
    conn.execute("""CREATE TABLE findings (
        id INTEGER PRIMARY KEY,
        account_id INTEGER NOT NULL,
        asset_id INTEGER,
        rule_id VARCHAR(64) NOT NULL,
        resource_id VARCHAR(1024) NOT NULL,
        asset_type VARCHAR(64) NOT NULL,
        title VARCHAR(256) NOT NULL,
        severity VARCHAR(16) NOT NULL,
        status VARCHAR(16) NOT NULL DEFAULT 'open',
        why TEXT NOT NULL,
        remediation TEXT NOT NULL,
        compliance JSON NOT NULL DEFAULT '{}',
        related JSON NOT NULL DEFAULT '[]',
        first_seen_at DATETIME NOT NULL,
        last_seen_at DATETIME NOT NULL,
        resolved_at DATETIME,
        UNIQUE(account_id, rule_id, resource_id)
    )""")
    conn.commit()
    conn.close()

    init_db(url)

    conn = sqlite3.connect(path)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(findings)")}
    conn.close()
    assert {"suppressed_by", "suppressed_why"} <= columns


def test_legacy_issues_table_gets_evidence_status(tmp_path):
    path = tmp_path / "legacy-issues.db"
    url = _pre_existing_db(path)
    conn = sqlite3.connect(path)
    conn.execute("""CREATE TABLE issues (
        id INTEGER PRIMARY KEY,
        account_id INTEGER NOT NULL,
        issue_type VARCHAR(64) NOT NULL,
        path_hash VARCHAR(40) NOT NULL,
        title VARCHAR(256) NOT NULL,
        severity VARCHAR(16) NOT NULL,
        status VARCHAR(16) NOT NULL DEFAULT 'open',
        risk_score FLOAT NOT NULL DEFAULT 0,
        confidence FLOAT NOT NULL DEFAULT 1,
        resource_id VARCHAR(1024) NOT NULL,
        why TEXT NOT NULL,
        remediation TEXT NOT NULL,
        path JSON NOT NULL DEFAULT '[]',
        compliance JSON NOT NULL DEFAULT '{}',
        related JSON NOT NULL DEFAULT '[]',
        evidence JSON NOT NULL DEFAULT '[]',
        first_seen_at DATETIME NOT NULL,
        last_seen_at DATETIME NOT NULL,
        resolved_at DATETIME,
        UNIQUE(account_id, issue_type, path_hash)
    )""")
    conn.commit()
    conn.close()

    init_db(url)

    conn = sqlite3.connect(path)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(issues)")}
    default = next(
        row[4] for row in conn.execute("PRAGMA table_info(issues)")
        if row[1] == "evidence_status"
    )
    conn.close()
    assert "evidence_status" in columns
    assert str(default).strip("'") == "confirmed"
