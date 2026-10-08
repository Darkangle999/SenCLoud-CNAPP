"""Private S3 publishing for one-click CloudFormation onboarding.

CloudFormation's ``TemplateURL`` must resolve to an S3 object. The API stores
one deterministic, account-specific template in an Odineyes-owned *private*,
versioned bucket and returns a short-lived presigned URL for the AWS Console
quick-create page. Re-opening onboarding therefore reuses the same ExternalId
and template key, rather than minting a new trust configuration each time.
"""

from __future__ import annotations

import logging
import os
import re
from hashlib import sha256
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from urllib.parse import quote, urlsplit

logger = logging.getLogger(__name__)

# One shared, secret-free object serves every customer in the session flow.
# Nothing tenant-specific is in the body — ExternalId, the onboarding token and
# the callback URL all arrive as stack parameters through the launch URL. That
# is what lets a link be issued before any account id is known.
SHARED_TEMPLATE_KEY = "public/onboarding/odineyes-onboarding.yaml"


class OnboardingHostingConfigurationError(RuntimeError):
    """Raised when a deployment has not enabled one-click onboarding yet."""


@dataclass(frozen=True)
class HostedOnboardingTemplate:
    bucket: str
    key: str
    version_id: Optional[str]
    reused: bool
    template_url: str
    quick_create_url: str
    expires_at: datetime


def cloudformation_quick_create_url(
    *, template_url: str, region: str, stack_name: str, parameters: Optional[dict[str, str]] = None,
) -> str:
    """Build AWS's documented, parameter-prefilled Quick Create URL.

    ``template_url`` may be a short-lived, version-bound S3 presigned URL.
    Values are URL encoded once here, rather than being interpolated into a
    browser link by a caller.
    """
    parsed = urlsplit(template_url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise OnboardingHostingConfigurationError("CloudFormation template URL must be HTTPS")
    if not re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-\d", region):
        raise OnboardingHostingConfigurationError("onboarding template region must be a valid AWS region")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,127}", stack_name):
        raise OnboardingHostingConfigurationError("onboarding stack name is invalid")

    query = [
        f"templateURL={quote(template_url, safe='')}",
        f"stackName={quote(stack_name, safe='')}",
    ]
    for name, value in sorted((parameters or {}).items()):
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", name):
            raise OnboardingHostingConfigurationError("CloudFormation parameter name is invalid")
        query.append(f"param_{name}={quote(str(value), safe='')}")
    return (
        f"https://{region}.console.aws.amazon.com/cloudformation/home?region={quote(region, safe='')}"
        "#/stacks/create/review?" + "&".join(query)
    )


def public_api_url() -> str:
    """Return the externally reachable HTTPS API base URL.

    The callback is invoked by a Lambda in the customer's AWS account.  A
    browser-local URL (``localhost``) is not reachable from that Lambda and
    would make a stack appear to succeed while leaving the account unconnected.
    """
    value = os.environ.get("ODINEYES_PUBLIC_API_URL", "").strip().rstrip("/")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise OnboardingHostingConfigurationError(
            "ODINEYES_PUBLIC_API_URL must be a public HTTPS URL, for example "
            "https://api.example.com"
        )
    return value


def _bucket_name() -> str:
    bucket = os.environ.get("ODINEYES_ONBOARDING_TEMPLATE_BUCKET", "").strip()
    # Keep this validation intentionally conservative; it catches ARNs, paths
    # and accidental URLs before boto3 produces a less useful error.
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket):
        raise OnboardingHostingConfigurationError(
            "ODINEYES_ONBOARDING_TEMPLATE_BUCKET must name the private S3 bucket "
            "that hosts one-click onboarding templates"
        )
    return bucket


def _region() -> str:
    return (
        os.environ.get("ODINEYES_ONBOARDING_TEMPLATE_REGION")
        or os.environ.get("AWS_REGION")
        or os.environ.get("AWS_DEFAULT_REGION")
        or "us-east-1"
    )


def _template_prefix() -> str:
    """Return the configurable private S3 prefix for onboarding YAML files."""
    prefix = os.environ.get(
        "ODINEYES_ONBOARDING_TEMPLATE_PREFIX", "cloudformation-onboarding"
    ).strip().strip("/")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}", prefix) or ".." in prefix:
        raise OnboardingHostingConfigurationError(
            "ODINEYES_ONBOARDING_TEMPLATE_PREFIX must be a safe S3 key prefix"
        )
    return prefix


def template_object_key(account_identifier: str) -> str:
    """Build the stable S3 key for an AWS account's reusable YAML file."""
    if not re.fullmatch(r"\d{12}", account_identifier):
        raise OnboardingHostingConfigurationError(
            "account_identifier must be a 12-digit AWS account id for hosted onboarding"
        )
    return f"{_template_prefix()}/aws/{account_identifier}/onboarding.yaml"


def _is_missing_s3_object(exc: Exception) -> bool:
    """Whether a boto ClientError represents only an absent object."""
    response: Any = getattr(exc, "response", {})
    code = str((response.get("Error") or {}).get("Code", "")) if isinstance(response, dict) else ""
    return code in {"404", "NoSuchKey", "NotFound"}


def publish_cloudformation_template(
    *, account_identifier: str, template: str, quick_create_parameters: Optional[dict[str, str]] = None,
) -> HostedOnboardingTemplate:
    """Store or reuse ``template`` and build a version-bound launch URL.

    The template key is stable for an AWS account. Its checksum is stored as
    S3 object metadata, so an identical retry performs no write and simply
    mints a new 15-minute URL. When the template changes, bucket versioning
    preserves the earlier YAML while the launch URL is bound to the new object
    version. The workload identity needs only ``s3:PutObject`` and
    ``s3:GetObject`` on the configured prefix.
    """
    bucket = _bucket_name()
    region = _region()
    key = template_object_key(account_identifier)
    body = template.encode("utf-8")
    template_sha256 = sha256(body).hexdigest()

    try:
        import boto3

        client = boto3.client("s3", region_name=region)
        existing: Optional[dict[str, Any]] = None
        try:
            existing = client.head_object(Bucket=bucket, Key=key)
        except Exception as exc:  # boto has no stable exception class without botocore
            if not _is_missing_s3_object(exc):
                raise

        metadata = (existing or {}).get("Metadata") or {}
        reused = metadata.get("template-sha256") == template_sha256
        version_id = (existing or {}).get("VersionId") if reused else None
        if not reused:
            written = client.put_object(
                Bucket=bucket,
                Key=key,
                Body=body,
                ContentType="application/x-yaml; charset=utf-8",
                CacheControl="no-store",
                ServerSideEncryption="AES256",
                Metadata={
                    "template-sha256": template_sha256,
                    "template-format": "cloudformation-yaml",
                },
            )
            version_id = written.get("VersionId")

        presign_params: dict[str, str] = {"Bucket": bucket, "Key": key}
        if version_id:
            presign_params["VersionId"] = version_id
        template_url = client.generate_presigned_url(
            "get_object",
            Params=presign_params,
            ExpiresIn=900,
            HttpMethod="GET",
        )
    except OnboardingHostingConfigurationError:
        raise
    except Exception as exc:  # noqa: BLE001 - preserve the provider diagnostic
        raise OnboardingHostingConfigurationError(
            "Odineyes could not publish the private CloudFormation template: "
            f"{exc}"
        ) from exc

    stack_name = f"odineyes-onboarding-{account_identifier}"
    quick_create_url = cloudformation_quick_create_url(
        template_url=template_url,
        region=region,
        stack_name=stack_name,
        parameters=quick_create_parameters,
    )
    return HostedOnboardingTemplate(
        bucket=bucket,
        key=key,
        version_id=version_id,
        reused=reused,
        template_url=template_url,
        quick_create_url=quick_create_url,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
    )


# --------------------------------------------------------------- shared object
@dataclass(frozen=True)
class SharedOnboardingTemplate:
    bucket: str
    key: str
    template_url: str
    checksum: str
    reused: bool


_SECRET_MARKERS = ("ODINEYES_API_SECRET", "api_secret", "AKIA")


def shared_template_key() -> str:
    return f"{_template_prefix()}/{SHARED_TEMPLATE_KEY}"


def assert_template_is_generic(template: str) -> None:
    """Refuse to publish a shared body carrying tenant-specific values.

    This object is served to every customer from one key. A secret in it would
    be published to all of them at once, so the check runs before the upload
    rather than trusting the caller to have passed the right template.
    """
    found = [marker for marker in _SECRET_MARKERS if marker in template]
    if found:
        raise OnboardingHostingConfigurationError(
            f"refusing to publish a shared onboarding template containing {found}. "
            "Only the parameterised, secret-free template may be published here."
        )
    if "sts:ExternalId" in template and "!Ref ExternalId" not in template:
        raise OnboardingHostingConfigurationError(
            "shared onboarding template hard-codes an ExternalId; it must be a "
            "CloudFormation parameter so one object can serve every customer"
        )


def publish_shared_template(
    template: str, *, url_ttl_seconds: int = 3600
) -> SharedOnboardingTemplate:
    """Upload the generic template once and return a CloudFormation-usable URL.

    Idempotent on content: an unchanged template performs no write, it just
    mints a fresh presigned URL. The bucket stays private — CloudFormation
    fetches ``TemplateURL`` with the *caller's* credentials, so an unsigned URL
    to our bucket would be AccessDenied for every customer outside our account.
    The signature travels in the URL instead, and its lifetime is matched to the
    onboarding link's so a template URL cannot die before the link does.
    """
    assert_template_is_generic(template)
    bucket = _bucket_name()
    region = _region()
    key = shared_template_key()
    body = template.encode("utf-8")
    checksum = sha256(body).hexdigest()

    try:
        import boto3

        client = boto3.client("s3", region_name=region)
        reused = False
        try:
            head = client.head_object(Bucket=bucket, Key=key)
            reused = (head.get("Metadata") or {}).get("template-sha256") == checksum
        except Exception as exc:  # boto has no stable exception class without botocore
            if not _is_missing_s3_object(exc):
                raise

        if not reused:
            # No ACL is set. Modern buckets default to BucketOwnerEnforced,
            # which disables ACLs outright — ACL=public-read there fails the
            # upload with AccessControlListNotSupported rather than being
            # ignored.
            client.put_object(
                Bucket=bucket,
                Key=key,
                Body=body,
                ContentType="application/x-yaml; charset=utf-8",
                CacheControl="public, max-age=300",
                ServerSideEncryption="AES256",
                Metadata={
                    "template-sha256": checksum,
                    "template-format": "cloudformation-yaml",
                },
            )

        template_url = client.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket, "Key": key},
            ExpiresIn=max(900, url_ttl_seconds),
            HttpMethod="GET",
        )
    except OnboardingHostingConfigurationError:
        raise
    except Exception as exc:  # noqa: BLE001 - preserve the provider diagnostic
        raise OnboardingHostingConfigurationError(
            f"could not publish the shared CloudFormation template: {exc}"
        ) from exc

    return SharedOnboardingTemplate(
        bucket=bucket, key=key, template_url=template_url,
        checksum=checksum, reused=reused,
    )


def quick_create_url(
    *,
    template_url: str,
    parameters: dict[str, str],
    stack_name: str,
    console_region: Optional[str] = None,
) -> str:
    """Quick-create URL with every stack parameter pre-filled.

    The customer clicks this while signed into whichever AWS account they want
    connected — that choice is theirs to make in the console, and the stack
    reports back which account it actually ran in. Nothing here declares an
    account id on their behalf.

    Parameter values ride in the query string, so treat this URL as sensitive:
    it carries the onboarding token. That token is single-use and short-lived
    precisely so a link sitting in browser history or a screen share is not a
    standing credential.
    """
    return cloudformation_quick_create_url(
        template_url=template_url,
        region=console_region or _region(),
        stack_name=stack_name,
        parameters=parameters,
    )


# ------------------------------------------------------------ readiness check
@dataclass(frozen=True)
class HostingCheck:
    name: str
    status: str  # pass | fail | warn | info
    detail: str = ""


def check_hosting(session: Any = None) -> list[HostingCheck]:
    """Diagnose whether one-click onboarding can actually work.

    Every failure here is one a customer would otherwise hit as a dead launch
    link, so it is worth answering before sending one rather than after. Never
    raises: a check that cannot run reports itself as a check.
    """
    from odineyes.core import onboarding_token

    checks: list[HostingCheck] = []

    def add(name: str, status: str, detail: str = "") -> None:
        checks.append(HostingCheck(name, status, detail))

    # A warn, not a fail: without it only the *automatic callback* is
    # unavailable. Links generated with the callback toggle off still resolve
    # and are completed by manual registration, so failing here would block the
    # one path a deployment without a public endpoint can actually use.
    try:
        add("Public API URL", "pass", public_api_url())
    except OnboardingHostingConfigurationError:
        add(
            "Public API URL", "warn",
            "not set, so the automatic callback is unavailable — a Lambda in the "
            "customer's account cannot reach a localhost API. Generate links with "
            "the callback toggle OFF and complete them under Manual deployment. "
            "Set ODINEYES_PUBLIC_API_URL to a public HTTPS origin to enable it.",
        )

    if onboarding_token.secret_is_configured():
        add("Token signing secret", "pass", "set, 32+ characters")
    else:
        add(
            "Token signing secret", "fail",
            f"{onboarding_token.SECRET_ENV} is unset or too short; tokens cannot "
            "be signed and every callback would be forgeable",
        )

    # IAM validates the trust policy's principal when the *customer's* stack
    # stores it, so a principal that does not exist fails their stack with
    # "Invalid principal in policy" — a CREATE_FAILED on something we sent them.
    try:
        from odineyes.core.iac_templates import odineyes_scanner_principal_arn

        principal = odineyes_scanner_principal_arn()
        if principal.endswith(":root"):
            add("Scanner principal", "fail",
                f"{principal} — account root cannot be trusted for one-click "
                "onboarding; name the specific IAM role or user")
        else:
            add("Scanner principal", "pass", principal)
    except Exception as exc:  # noqa: BLE001 - configuration errors are the point
        add("Scanner principal", "fail", str(exc)[:300])

    try:
        bucket = _bucket_name()
        add("Template bucket", "pass", bucket)
    except OnboardingHostingConfigurationError as exc:
        add("Template bucket", "fail", str(exc))
        return checks

    region = _region()
    try:
        key = shared_template_key()
    except OnboardingHostingConfigurationError as exc:
        add("Template key", "fail", str(exc))
        return checks
    add("Template key", "info", f"s3://{bucket}/{key}")

    if session is None:
        try:
            import boto3

            session = boto3.Session()
        except ImportError:
            add("AWS checks", "warn", "boto3 unavailable; skipped live checks")
            return checks

    s3 = session.client("s3", region_name=region)
    try:
        s3.head_bucket(Bucket=bucket)
        add("Bucket reachable", "pass", f"head_bucket succeeded in {region}")
    except Exception:  # noqa: BLE001 - fall back to the object-level probe
        # head_bucket needs s3:ListBucket on the bucket itself, which the
        # least-privilege publish policy intentionally omits. Publishing needs
        # only object-level calls, so probe the real template key before
        # declaring the bucket unusable: a missing object (404) still proves
        # the credentials are valid for this bucket and GetObject is allowed.
        try:
            head = s3.head_object(Bucket=bucket, Key=key)
        except Exception as probe_exc:  # noqa: BLE001
            if _is_missing_s3_object(probe_exc):
                add(
                    "Bucket reachable", "pass",
                    f"head_bucket was denied (s3:ListBucket not granted), but "
                    f"object-level access works in {region}; the template is not "
                    f"uploaded yet — publish it below. Add s3:ListBucket on the "
                    f"bucket to let the bucket-level probe succeed too",
                )
            else:
                add("Bucket reachable", "fail", str(probe_exc)[:200])
                return checks
        else:
            add(
                "Bucket reachable", "pass",
                f"head_bucket was denied (s3:ListBucket not granted), but the "
                f"template object is readable in {region} "
                f"({head.get('ContentLength', 0)} bytes)",
            )

    try:
        status = s3.get_bucket_policy_status(Bucket=bucket)["PolicyStatus"]
        is_public = bool(status.get("IsPublic"))
        add(
            "Bucket policy is not public", "pass" if not is_public else "fail",
            "IsPublic: false" if not is_public
            else "IsPublic: true — a security product should not run a public "
                 "bucket its own scanner would flag",
        )
    except Exception as exc:  # noqa: BLE001 - an absent policy is fine
        add("Bucket policy is not public", "info", f"no bucket policy ({type(exc).__name__})")

    try:
        head = s3.head_object(Bucket=bucket, Key=key)
        add(
            "Template published", "pass",
            f"{head.get('ContentLength', 0)} bytes, sha256 "
            f"{(head.get('Metadata') or {}).get('template-sha256', '?')[:12]}",
        )
    except Exception as exc:  # noqa: BLE001
        if _is_missing_s3_object(exc):
            add("Template published", "warn", "not uploaded yet; publish it below")
        else:
            add("Template published", "fail", str(exc)[:200])

    # The decisive check. Everything above can pass while CloudFormation still
    # refuses the URL — that is exactly how a CloudFront delivery path ships
    # broken ("TemplateURL must be a supported URL"). Only CloudFormation can
    # answer whether it will accept the URL, so ask it.
    try:
        from odineyes.core.iac_templates import cloudformation_parameterized_template

        published = publish_shared_template(cloudformation_parameterized_template("managed"))
        session.client("cloudformation", region_name=region).validate_template(
            TemplateURL=published.template_url
        )
        add("CloudFormation accepts the URL", "pass",
            "validate_template accepted the presigned S3 URL")
    except Exception as exc:  # noqa: BLE001 - this is the check's whole point
        response = getattr(exc, "response", None)
        message = (response or {}).get("Error", {}).get("Message", str(exc)) if isinstance(response, dict) else str(exc)
        add("CloudFormation accepts the URL", "fail",
            f"{message[:200]} — customers would see this instead of a stack")

    return checks


def hosting_is_ready(checks: list[HostingCheck]) -> bool:
    return not any(check.status == "fail" for check in checks)
