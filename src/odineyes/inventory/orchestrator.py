"""Multi-account scan orchestration.

For every active registered account: build a boto3 session (STS assume-role
when the account row carries a ``role_arn``, ambient credentials otherwise),
collect raw resources, persist through the standard scan path, then run the
rules and attack-path engines. Accounts scan in parallel — each worker uses
its own boto3 session and its own DB session, so no shared state crosses
threads.

The session and collector factories are injectable so the whole pipeline runs
under test without AWS or network access.
"""

from __future__ import annotations

import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from threading import Lock
from typing import Any, Callable, Optional

import boto3

from odineyes.db.base import session_scope
from odineyes.db.models import CloudAccount
from odineyes.inventory.aws_raw_collector import AwsRawCollector
from odineyes.inventory.repository import FindingSyncStats, IssueSyncStats
from odineyes.inventory.service import InventoryService, ScanResult

logger = logging.getLogger(__name__)

ASSUME_ROLE_SESSION_NAME = "odineyes-inventory-scan"
_scan_locks_guard = Lock()
_scan_locks: dict[tuple[str, str], Lock] = {}


class ScanAlreadyRunning(RuntimeError):
    pass


def _trivy_misconfig_mode() -> str:
    """``ODINEYES_TRIVY_MISCONFIG`` controls CSPM engine #2: ``auto`` (default)
    runs Trivy's AWS misconfig checks whenever the binary is installed, ``on``
    demands them (a missing binary is reported, never silently dropped), and
    ``off`` disables the step entirely."""
    return (os.environ.get("ODINEYES_TRIVY_MISCONFIG") or "auto").strip().lower()


def _aws_scanner_backend(account_identifier: str) -> str:
    backend = os.getenv("ODINEYES_AWS_SCANNER_BACKEND", "python").strip().lower()
    if backend not in {"python", "go", "shadow"}:
        raise RuntimeError(
            "ODINEYES_AWS_SCANNER_BACKEND must be one of: python, go, shadow"
        )
    raw_allowlist = os.getenv("ODINEYES_AWS_SCANNER_ACCOUNT_ALLOWLIST", "").strip()
    if not raw_allowlist or backend == "python":
        return backend
    allowlist = {item.strip() for item in raw_allowlist.split(",") if item.strip()}
    if any(len(item) != 12 or not item.isdigit() for item in allowlist):
        raise RuntimeError(
            "ODINEYES_AWS_SCANNER_ACCOUNT_ALLOWLIST must be a comma-separated "
            "list of 12-digit AWS account ids"
        )
    return backend if account_identifier in allowlist else "python"


@contextmanager
def _account_scan_guard(account: "AccountRef"):
    """Prevent two scans for one tenant from interleaving in this process.

    Interleaved snapshots can retire assets observed by the other scan. A
    distributed deployment should additionally use one scanner worker or a DB
    advisory lock; this guard covers the current single API-process topology.
    """
    key = (account.provider, account.identifier)
    with _scan_locks_guard:
        lock = _scan_locks.setdefault(key, Lock())
        acquired = lock.acquire(blocking=False)
    if not acquired:
        raise ScanAlreadyRunning(
            f"scan already running for {account.provider} account {account.identifier}"
        )
    try:
        yield
    finally:
        with _scan_locks_guard:
            lock.release()
            if _scan_locks.get(key) is lock:
                _scan_locks.pop(key, None)


@dataclass(frozen=True)
class AccountRef:
    """Detached snapshot of a CloudAccount row — safe to hand across threads."""
    identifier: str
    name: Optional[str]
    role_arn: Optional[str]
    provider: str = "aws"
    external_id: Optional[str] = None
    # Regions removed from the discovery sweep (SCP-blocked etc.). Empty tuple
    # = scan every enabled region, dormant ones included.
    excluded_regions: tuple[str, ...] = ()


@dataclass
class AccountScanResult:
    account_identifier: str
    status: str                              # completed | failed
    scan: Optional[ScanResult] = None
    findings: Optional[FindingSyncStats] = None
    issues: Optional[IssueSyncStats] = None
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"account_identifier": self.account_identifier, "status": self.status}
        if self.scan:
            out["scan"] = {"scan_job_id": self.scan.scan_job_id, "found": self.scan.found,
                           "new": self.scan.new, "changed": self.scan.changed,
                           "deleted": self.scan.deleted, "errors": self.scan.errors,
                           "partial": self.scan.partial}
        if self.findings:
            out["findings"] = {"total": self.findings.total, "new": self.findings.new,
                               "reopened": self.findings.reopened, "resolved": self.findings.resolved}
        if self.issues:
            out["issues"] = {"total": self.issues.total, "new": self.issues.new,
                             "reopened": self.issues.reopened, "resolved": self.issues.resolved}
        if self.error:
            out["error"] = self.error
        return out


SessionFactory = Callable[[AccountRef], boto3.Session]
CollectorFactory = Callable[[boto3.Session, str], Any]


class MultiAccountOrchestrator:
    def __init__(
        self,
        service: Optional[InventoryService] = None,
        *,
        region: str = "us-east-1",
        max_workers: int = 4,
        session_factory: Optional[SessionFactory] = None,
        collector_factory: Optional[CollectorFactory] = None,
    ):
        self.service = service or InventoryService(auto_init=False)
        self.region = region
        self.max_workers = max(1, max_workers)
        self._session_factory = session_factory or self._default_session
        # When injected (tests), the AWS-style (session, region) factory wins;
        # when None, the collector is dispatched per provider in _make_collector.
        self._collector_factory = collector_factory

    def _default_session(self, account: AccountRef) -> boto3.Session:
        """Build a boto3 session for scanning.

        Primary path (production): AssumeRole into the account's read-only role.

        Ambient fallback is allowed ONLY when the caller's own STS identity is
        the SAME account we're scanning (local dev scanning your own account).
        It is NEVER used to scan a different account — doing so silently stores
        the central account's resources under the target account's id, which is
        the "scan succeeds but the account is empty/wrong" bug. In that case we
        raise with an actionable message instead.
        """
        # Scanning your OWN account? Use ambient credentials directly — no
        # AssumeRole needed. Root CAN make read-only Describe/List/Get calls; it
        # only can't call sts:AssumeRole. So a self-account scan works even with
        # root creds. Checked FIRST so we never attempt (and fail) an assume the
        # target doesn't require.
        caller = self._caller_account()
        if caller is not None and caller == account.identifier:
            return boto3.Session(region_name=self.region)

        # Different account → must assume its cross-account role.
        if account.role_arn:
            try:
                sts = boto3.client("sts", region_name=self.region)
                kwargs: dict[str, Any] = {
                    "RoleArn": account.role_arn,
                    "RoleSessionName": ASSUME_ROLE_SESSION_NAME,
                    "DurationSeconds": 3600,
                }
                if account.external_id:
                    kwargs["ExternalId"] = account.external_id
                creds = sts.assume_role(**kwargs)["Credentials"]
                return boto3.Session(
                    aws_access_key_id=creds["AccessKeyId"],
                    aws_secret_access_key=creds["SecretAccessKey"],
                    aws_session_token=creds["SessionToken"],
                    region_name=self.region,
                )
            except Exception as e:  # noqa: BLE001
                raise RuntimeError(
                    f"cannot scan account {account.identifier}: AssumeRole failed "
                    f"({e}). The scanner's credentials belong to account "
                    f"{caller or 'unknown'}. Check that the scanner principal has "
                    "sts:AssumeRole permission, the target role trusts that exact "
                    "principal, and the trust policy ExternalId matches Odineyes."
                ) from e

        raise RuntimeError(
            f"cannot scan account {account.identifier}: no role_arn registered and "
            f"the scanner's credentials belong to account {caller or 'unknown'}."
        )

    def _caller_account(self) -> Optional[str]:
        """The 12-digit account id of whatever credentials this process runs as,
        or None if it can't be resolved."""
        try:
            return boto3.client("sts", region_name=self.region) \
                .get_caller_identity().get("Account")
        except Exception:  # noqa: BLE001 — best-effort identity check
            return None

    def verify_access(self, account: AccountRef, *, deep: bool = False) -> dict[str, Any]:
        """Automated version of the manual "assume-role then describe-instances"
        diagnosis — independent checks, each reported separately so the UI can
        say exactly which stage broke instead of a raw boto3 traceback:

          1. assume  — can we get a session for this account at all (role trust
             + ExternalId + non-root caller)?
          2. read    — does that session actually have read permissions (a
             misconfigured/too-narrow policy assumes fine but reads nothing)?
          3. permissions (deep only) — one cheap probe per collection domain
             plus the negative probes that must stay denied, so a stale template
             version or an SCP shows up as a named coverage gap rather than as
             quietly missing findings on the first scan.

        Deep mode costs ~50 read-only API calls, so it is opt-in: the onboarding
        poller stays on the cheap path, the operator's Verify button uses it.

        Never raises — always returns a result dict, even on total failure."""
        result: dict[str, Any] = {
            "account_identifier": account.identifier,
            "assume": {"ok": False, "error": None},
            "read": {"ok": False, "error": None, "sample": None},
        }
        try:
            session = self._default_session(account)
        except Exception as e:  # noqa: BLE001
            result["assume"]["error"] = str(e)
            return result
        result["assume"]["ok"] = True

        try:
            # A cheap, always-granted-by-the-onboarding-policy read call —
            # proves the policy is actually attached, not just the trust.
            regions = session.client("ec2", region_name=self.region).describe_instances(MaxResults=5)
            n = sum(len(r.get("Instances", [])) for r in regions.get("Reservations", []))
            result["read"]["ok"] = True
            result["read"]["sample"] = {"ec2_instances_seen": n}
        except Exception as e:  # noqa: BLE001
            result["read"]["error"] = str(e)

        if deep:
            from odineyes.core.onboarding_validator import validate

            result["permissions"] = validate(
                session, account.identifier, self.region,
            ).to_dict()
        return result

    def _make_collector(self, account: AccountRef) -> Any:
        """Dispatch a read-only collector by provider. An injected
        collector_factory (tests) overrides and follows the AWS-style
        (session, region) contract."""
        if self._collector_factory is not None:
            return self._collector_factory(self._session_factory(account), self.region)
        if account.provider == "aws":
            backend = _aws_scanner_backend(account.identifier)
            if backend == "python":
                return AwsRawCollector(region=self.region, session=self._default_session(account))

            from odineyes.inventory.go_aws_collector import (
                GoAwsCollector,
                ShadowAwsCollector,
            )

            go_collector = GoAwsCollector(
                account_identifier=account.identifier,
                role_arn=account.role_arn,
                external_id=account.external_id,
                region=self.region,
                excluded_regions=list(account.excluded_regions),
            )
            if backend == "go":
                return go_collector
            return ShadowAwsCollector(
                AwsRawCollector(region=self.region, session=self._default_session(account)),
                go_collector,
            )
        if account.provider == "azure":
            from odineyes.inventory.azure_collector import AzureCollector
            return AzureCollector(subscription_id=account.identifier)
        if account.provider == "gcp":
            from odineyes.inventory.gcp_collector import GcpCollector
            return GcpCollector(project=account.identifier)
        raise ValueError(f"no collector registered for provider '{account.provider}'")

    def scan_account(self, account: AccountRef) -> AccountScanResult:
        """One account end to end: collect → persist → rules → paths.
        Never raises — a failed account reports, it doesn't sink the fleet."""
        scan_job_id: Optional[int] = None
        try:
            with _account_scan_guard(account):
                # The job starts before AssumeRole/collection. A newly connected
                # account can therefore show a useful running/failed status even
                # when AWS denies access before any resource is collected.
                scan_job_id = self.service.begin_scan(
                    account.provider, account.identifier,
                    account_name=account.name, role_arn=account.role_arn,
                )
                collector = self._make_collector(account)
                resources = collector.collect()
                scan = self.service.persist_scan(
                    account.provider, account.identifier, resources,
                    account_name=account.name, role_arn=account.role_arn,
                    # Missing attributes identify a legacy/injected collector
                    # whose return value follows the original full-snapshot contract.
                    authoritative_scopes=getattr(collector, "authoritative_scopes", None),
                    collection_errors=getattr(collector, "collection_errors", ()),
                    scan_job_id=scan_job_id,
                )
                findings = self.service.evaluate_findings(account.provider, account.identifier)
                issues = self.service.evaluate_issues(account.provider, account.identifier)
                # CSPM engine #2: Trivy's built-in AWS checks (AVD-AWS-*) merged
                # into the same findings table. Skipped, never faked, when the
                # binary or credentials are missing - and a failure here never
                # sinks the inventory scan.
                mode = _trivy_misconfig_mode()
                if mode != "off" and account.provider == "aws":
                    try:
                        from odineyes.cloud import trivy_misconfig
                        if mode == "on" or trivy_misconfig.available():
                            mis = self.service.scan_trivy_misconfig(
                                account.provider, account.identifier,
                                session=self._default_session(account),
                            )
                            logger.info("trivy misconfig for %s: %s (%s findings)",
                                        account.identifier, mis.get("status"),
                                        mis.get("findings", 0))
                    except Exception:  # noqa: BLE001 - optional engine must not fail the scan
                        logger.warning("trivy misconfig step failed for %s",
                                       account.identifier, exc_info=True)
                try:
                    # Automatically capture a compliance snapshot based on the new findings
                    self.service.snapshot_compliance(account.provider, account.identifier, ["CIS", "SOC2", "NIST", "PCI-DSS"])
                except Exception:
                    pass  # Do not fail the inventory scan if compliance scoring fails
                return AccountScanResult(account.identifier, "completed", scan, findings, issues)
        except Exception as exc:  # noqa: BLE001 — isolate per-account failure
            msg = str(exc)
            # Surface a clear, actionable message for the most common credential
            # misconfiguration: running the scanner as the AWS root user.
            if "Roles may not be assumed by root accounts" in msg:
                msg = (
                    f"AWS rejected AssumeRole for account {account.identifier}: "
                    "you are running Odineyes with ROOT account credentials. "
                    "AWS does not allow root to call sts:AssumeRole. "
                    "Fix: create a regular IAM User (e.g. OdineyesScanner), "
                    "grant it sts:AssumeRole permission, generate access keys, "
                    "and run 'aws configure' to switch credentials."
                )
            if scan_job_id is not None:
                try:
                    self.service.fail_scan(scan_job_id, msg)
                except Exception:  # noqa: BLE001 — keep the account result usable
                    logger.exception("could not record failed scan job %s", scan_job_id)
            logger.error("scan failed for account %s: %s", account.identifier, msg)
            return AccountScanResult(account.identifier, "failed", error=msg)

    def scan_all(self, provider: str = "aws") -> list[AccountScanResult]:
        """Scan every active registered account of the provider in parallel."""
        # Read the roster from the same store the service writes. Relying on a
        # mutable process-global engine made explicit/test databases scan the
        # wrong account set under concurrency.
        with session_scope(self.service.database_url) as db:
            accounts = [
                AccountRef(
                    a.account_identifier, a.name, a.role_arn, provider, a.external_id,
                    excluded_regions=tuple(json.loads(a.excluded_regions or "[]")),
                )
                for a in db.query(CloudAccount)
                .filter(CloudAccount.provider == provider, CloudAccount.is_active.is_(True))
                .all()
            ]
        if not accounts:
            return []
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(accounts))) as pool:
            return list(pool.map(self.scan_account, accounts))
