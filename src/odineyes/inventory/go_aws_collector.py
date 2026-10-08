"""Bounded subprocess adapter for the Go AWS inventory scanner.

The Go process receives its request over stdin and loads the standard AWS
credential chain itself. Temporary AssumeRole credentials therefore never
cross a command line, environment variable, log record, or Python object.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Optional

from odineyes.inventory.collection import CollectionError, CollectionScope

logger = logging.getLogger(__name__)

_SCHEMA_VERSION = "1.0"
_DEFAULT_TIMEOUT_SECONDS = 15 * 60
_MAX_RESPONSE_BYTES = 256 * 1024 * 1024
_MAX_STDERR_BYTES = 32 * 1024

RawResource = tuple[str, dict[str, Any]]


class GoAwsCollector:
    """Expose the Go scanner through the existing ``collector.collect`` contract."""

    def __init__(
        self,
        *,
        account_identifier: str,
        role_arn: Optional[str],
        external_id: Optional[str],
        region: str = "us-east-1",
        regions: Optional[list[str]] = None,
        excluded_regions: Optional[list[str]] = None,
        max_workers: Optional[int] = None,
        max_items_per_operation: Optional[int] = None,
        timeout_seconds: Optional[int] = None,
        binary_path: Optional[str] = None,
    ) -> None:
        self.account_identifier = account_identifier
        self.role_arn = role_arn
        self.external_id = external_id
        self.region = region
        self.regions = list(regions or [])
        # Regions the operator removed from the sweep (e.g. SCP-blocked ones).
        # Discovery still runs first: the sweep covers every enabled region
        # minus these, so new AWS regions are picked up automatically.
        self.excluded_regions = list(excluded_regions or [])
        self.max_workers = max_workers
        self.max_items_per_operation = max_items_per_operation
        self.timeout_seconds = timeout_seconds or _env_int(
            "ODINEYES_GO_SCANNER_TIMEOUT_SECONDS",
            _DEFAULT_TIMEOUT_SECONDS,
            minimum=30,
            maximum=3600,
        )
        self.binary_path = binary_path or os.getenv(
            "ODINEYES_GO_SCANNER_PATH",
            "odineyes-scanner",
        )
        self.authoritative_scopes: set[CollectionScope] = set()
        self.collection_errors: list[CollectionError] = []
        self.metrics: dict[str, Any] = {}

    def collect(self) -> list[RawResource]:
        request = {
            "schema_version": _SCHEMA_VERSION,
            "provider": "aws",
            "account_identifier": self.account_identifier,
            "role_arn": self.role_arn or "",
            "external_id": self.external_id or "",
            "home_region": self.region,
            "regions": self.regions,
            "excluded_regions": self.excluded_regions,
            "timeout_seconds": self.timeout_seconds,
        }
        if self.max_workers is not None:
            request["max_workers"] = self.max_workers
        if self.max_items_per_operation is not None:
            request["max_items_per_operation"] = self.max_items_per_operation

        executable = _resolve_binary(self.binary_path)
        response = _execute_scanner(
            executable,
            json.dumps(request, separators=(",", ":")).encode("utf-8"),
            timeout_seconds=self.timeout_seconds + 15,
        )
        resources, scopes, errors, metrics = _decode_response(
            response,
            expected_account=self.account_identifier,
        )
        self.authoritative_scopes = scopes
        self.collection_errors = errors
        self.metrics = metrics
        logger.info(
            "Go AWS scan completed for account %s: resources=%d regions=%s duration_ms=%s errors=%d",
            self.account_identifier,
            len(resources),
            metrics.get("regions_scanned"),
            metrics.get("duration_ms"),
            len(errors),
        )
        return resources


class ShadowAwsCollector:
    """Return Python results while comparing an isolated Go shadow collection."""

    def __init__(self, primary: Any, shadow: GoAwsCollector) -> None:
        self.primary = primary
        self.shadow = shadow
        self.authoritative_scopes: set[CollectionScope] = set()
        self.collection_errors: list[CollectionError] = []

    def collect(self) -> list[RawResource]:
        primary_resources = list(self.primary.collect())
        self.authoritative_scopes = set(
            getattr(self.primary, "authoritative_scopes", set())
        )
        self.collection_errors = list(
            getattr(self.primary, "collection_errors", [])
        )
        try:
            shadow_resources = self.shadow.collect()
        except Exception:  # noqa: BLE001 - shadow mode must never fail persistence
            logger.exception(
                "Go AWS shadow scan failed for account %s; Python results remain authoritative",
                self.shadow.account_identifier,
            )
            return primary_resources

        primary_counts = Counter(source_type for source_type, _ in primary_resources)
        shadow_counts = Counter(source_type for source_type, _ in shadow_resources)
        all_types = sorted(set(primary_counts) | set(shadow_counts))
        differences = {
            source_type: {
                "python": primary_counts[source_type],
                "go": shadow_counts[source_type],
            }
            for source_type in all_types
            if primary_counts[source_type] != shadow_counts[source_type]
        }
        missing_scopes = sorted(
            self.authoritative_scopes - self.shadow.authoritative_scopes,
            key=lambda item: (item[0], item[1] or ""),
        )
        extra_scopes = sorted(
            self.shadow.authoritative_scopes - self.authoritative_scopes,
            key=lambda item: (item[0], item[1] or ""),
        )
        if differences or missing_scopes or extra_scopes:
            logger.warning(
                "AWS scanner shadow mismatch for account %s: counts=%s missing_go_scopes=%s extra_go_scopes=%s",
                self.shadow.account_identifier,
                differences,
                missing_scopes,
                extra_scopes,
            )
        else:
            logger.info(
                "AWS scanner shadow parity passed for account %s across %d resource types",
                self.shadow.account_identifier,
                len(all_types),
            )
        return primary_resources


def _resolve_binary(binary_path: str) -> str:
    expanded = Path(binary_path).expanduser()
    if expanded.is_absolute() or expanded.parent != Path("."):
        if expanded.is_file():
            return str(expanded)
        raise RuntimeError(
            f"Go scanner binary not found at '{expanded}'. "
            "Build scanner-go/cmd/odineyes-scanner or set ODINEYES_GO_SCANNER_PATH."
        )
    resolved = shutil.which(binary_path)
    if resolved:
        return resolved
    raise RuntimeError(
        f"Go scanner binary '{binary_path}' is not on PATH. "
        "Build scanner-go/cmd/odineyes-scanner or set ODINEYES_GO_SCANNER_PATH."
    )


def _execute_scanner(
    executable: str,
    request: bytes,
    *,
    timeout_seconds: int,
) -> bytes:
    """Run without a shell and bound the response read before JSON decoding."""

    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        process = subprocess.Popen(  # noqa: S603 - executable is operator-configured
            [executable],
            stdin=subprocess.PIPE,
            stdout=stdout_file,
            stderr=stderr_file,
            shell=False,
        )
        try:
            process.communicate(input=request, timeout=timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.wait(timeout=10)
            raise RuntimeError(
                f"Go scanner timed out after {timeout_seconds} seconds"
            ) from exc

        stdout_file.seek(0)
        response = stdout_file.read(_MAX_RESPONSE_BYTES + 1)
        if len(response) > _MAX_RESPONSE_BYTES:
            raise RuntimeError(
                f"Go scanner response exceeded {_MAX_RESPONSE_BYTES} bytes"
            )
        stderr_file.seek(0)
        stderr = stderr_file.read(_MAX_STDERR_BYTES).decode("utf-8", errors="replace").strip()

    if not response:
        detail = f": {stderr}" if stderr else ""
        raise RuntimeError(
            f"Go scanner exited with code {process.returncode} without a response{detail}"
        )

    # Fatal scanner responses are JSON even when the exit code is non-zero. Let
    # the decoder surface that actionable AWS error before falling back to stderr.
    if process.returncode != 0:
        try:
            payload = json.loads(response)
        except (TypeError, ValueError):
            detail = f": {stderr}" if stderr else ""
            raise RuntimeError(
                f"Go scanner exited with code {process.returncode}{detail}"
            )
        fatal_error = payload.get("fatal_error") if isinstance(payload, dict) else None
        if fatal_error:
            raise RuntimeError(str(fatal_error))
        detail = f": {stderr}" if stderr else ""
        raise RuntimeError(f"Go scanner exited with code {process.returncode}{detail}")
    return response


def _decode_response(
    response: bytes,
    *,
    expected_account: str,
) -> tuple[
    list[RawResource],
    set[CollectionScope],
    list[CollectionError],
    dict[str, Any],
]:
    try:
        payload = json.loads(response)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("Go scanner returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("Go scanner response must be a JSON object")
    if payload.get("schema_version") != _SCHEMA_VERSION:
        raise RuntimeError(
            f"unsupported Go scanner schema_version {payload.get('schema_version')!r}"
        )
    if payload.get("account_identifier") != expected_account:
        raise RuntimeError(
            "Go scanner account mismatch: "
            f"expected {expected_account}, got {payload.get('account_identifier')!r}"
        )
    if payload.get("fatal_error"):
        raise RuntimeError(str(payload["fatal_error"]))

    raw_resources = payload.get("resources", [])
    if not isinstance(raw_resources, list):
        raise RuntimeError("Go scanner resources must be a list")
    resources: list[RawResource] = []
    from odineyes.inventory.normalizers import get_normalizer

    for index, item in enumerate(raw_resources):
        if not isinstance(item, dict):
            raise RuntimeError(f"Go scanner resource {index} must be an object")
        source_type = item.get("source_type")
        raw = item.get("raw")
        if not isinstance(source_type, str) or not source_type:
            raise RuntimeError(f"Go scanner resource {index} has no source_type")
        if not isinstance(raw, dict):
            raise RuntimeError(f"Go scanner resource {index} raw value must be an object")
        if get_normalizer(source_type) is None:
            raise RuntimeError(
                f"Go scanner resource {index} has unsupported source_type {source_type!r}"
            )
        resources.append((source_type, raw))

    scopes: set[CollectionScope] = set()
    raw_scopes = payload.get("authoritative_scopes", [])
    if not isinstance(raw_scopes, list):
        raise RuntimeError("Go scanner authoritative_scopes must be a list")
    for index, item in enumerate(raw_scopes):
        if not isinstance(item, dict) or not isinstance(item.get("source_type"), str):
            raise RuntimeError(f"Go scanner scope {index} is invalid")
        region = item.get("region")
        if region is not None and not isinstance(region, str):
            raise RuntimeError(f"Go scanner scope {index} region is invalid")
        scopes.add((item["source_type"], region))

    errors: list[CollectionError] = []
    raw_errors = payload.get("collection_errors", [])
    if not isinstance(raw_errors, list):
        raise RuntimeError("Go scanner collection_errors must be a list")
    for index, item in enumerate(raw_errors):
        if not isinstance(item, dict):
            raise RuntimeError(f"Go scanner collection error {index} is invalid")
        source_type = item.get("source_type")
        operation = item.get("operation")
        message = item.get("message")
        region = item.get("region")
        if not all(isinstance(value, str) for value in (source_type, operation, message)):
            raise RuntimeError(f"Go scanner collection error {index} is invalid")
        if region is not None and not isinstance(region, str):
            raise RuntimeError(f"Go scanner collection error {index} region is invalid")
        errors.append(
            CollectionError(
                source_type=source_type,
                operation=operation,
                message=message,
                region=region,
            )
        )

    metrics = payload.get("metrics") or {}
    if not isinstance(metrics, dict):
        raise RuntimeError("Go scanner metrics must be an object")
    return resources, scopes, errors, metrics


def _env_int(
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if value < minimum or value > maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}")
    return value
