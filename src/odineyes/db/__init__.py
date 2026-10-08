"""Persistence spine for Odineyes (Phase 1).

Dual-store by design: PostgreSQL for structured queries (this package) and
Neo4j for relationship traversal (``odineyes.graph``). SQLAlchemy keeps the
relational layer portable — sqlite for dev/test, Postgres in production via
``ODINEYES_DATABASE_URL``.
"""

from odineyes.db.base import (
    Base,
    get_engine,
    get_sessionmaker,
    init_db,
    session_scope,
)

__all__ = [
    "Base",
    "get_engine",
    "get_sessionmaker",
    "init_db",
    "session_scope",
]
