"""Short-lived, single-use onboarding session tokens (ported from CSPM-v2).

The per-account onboarding flow can store a token hash on the account row,
because the account is known before the link is issued. The session flow cannot:
a launch link is minted *before* anyone knows which AWS account will run the
stack, so there is no row to hang a hash on until the callback arrives.

This is a capability that expires instead. The token is a signed assertion —
"onboarding session S may report a role ARN, until time T" — minted here,
carried in the quick-create URL, and burned on first use against the session
row. It authorises exactly one callback and grants no read access.

Format:  v1.<session_id>.<expires_at>.<nonce>.<hex hmac>

Signed with ODINEYES_ONBOARDING_TOKEN_SECRET. Verification is constant-time and
checks, in order: shape, signature, expiry. Single-use is enforced by the caller
against the session row, because "already redeemed" is database state, not
something a signature can express.

The nonce exists so minting is never deterministic. An HMAC over
(session, expiry) alone returns the identical string for the same inputs within
the same second, which would make a regenerated link silently equal to the
previous one. With random bytes in the signed message, every mint is distinct.
"""

from __future__ import annotations

import hmac
import os
import secrets
import time
from dataclasses import dataclass
from hashlib import sha256

_TOKEN_VERSION = "v1"
# One hour: long enough to read the stack, short enough to matter.
DEFAULT_TTL_SECONDS = 3600
MIN_TTL_SECONDS = 60
MAX_TTL_SECONDS = 24 * 3600
MIN_SECRET_LENGTH = 32

SECRET_ENV = "ODINEYES_ONBOARDING_TOKEN_SECRET"


class OnboardingTokenError(RuntimeError):
    """Raised when a token is malformed, forged, or expired."""


@dataclass(frozen=True)
class OnboardingToken:
    session_id: str
    expires_at: int
    value: str
    nonce: str = ""

    @property
    def seconds_remaining(self) -> int:
        return max(0, self.expires_at - int(time.time()))


def secret_is_configured() -> bool:
    """Whether tokens can be signed at all. Used by the hosting preflight."""
    return len(os.environ.get(SECRET_ENV, "").strip()) >= MIN_SECRET_LENGTH


def _signing_secret() -> bytes:
    secret = os.environ.get(SECRET_ENV, "").strip()
    if len(secret) < MIN_SECRET_LENGTH:
        raise OnboardingTokenError(
            f"{SECRET_ENV} must be set to at least {MIN_SECRET_LENGTH} characters. "
            "Without it, onboarding tokens cannot be signed and any caller could "
            "forge a role-ARN callback."
        )
    return secret.encode("utf-8")


def _sign(session_id: str, expires_at: int, nonce: str) -> str:
    message = f"{_TOKEN_VERSION}.{session_id}.{expires_at}.{nonce}".encode()
    return hmac.new(_signing_secret(), message, sha256).hexdigest()


def new_session_id() -> str:
    """Opaque id for a pending onboarding, safe to place in a URL."""
    return secrets.token_urlsafe(24)


def looks_like_session_token(token: str) -> bool:
    """Cheap shape test used to route a callback to the session flow.

    The per-account token is ``secrets.token_urlsafe`` — URL-safe base64, no
    dots. This one is dot-delimited by construction, so the two never collide.
    """
    return token.startswith(f"{_TOKEN_VERSION}.") and token.count(".") == 4


def mint(session_id: str, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> OnboardingToken:
    """Mint a fresh token. Never returns the same value twice.

    Two calls with identical arguments produce different tokens, because the
    nonce is random and part of the signed message. Callers therefore cannot
    accidentally hand out a stale link by reusing a session id.
    """
    if not session_id:
        raise OnboardingTokenError("session_id is required")
    if "." in session_id:
        # The token is dot-delimited, so a dotted session id would shift every
        # field and let one session's token be read as another's.
        raise OnboardingTokenError("session_id must not contain '.'")

    ttl = max(MIN_TTL_SECONDS, min(int(ttl_seconds), MAX_TTL_SECONDS))
    expires_at = int(time.time()) + ttl
    nonce = secrets.token_urlsafe(12)
    signature = _sign(session_id, expires_at, nonce)
    return OnboardingToken(
        session_id=session_id,
        expires_at=expires_at,
        nonce=nonce,
        value=f"{_TOKEN_VERSION}.{session_id}.{expires_at}.{nonce}.{signature}",
    )


def verify(token: str) -> OnboardingToken:
    """Return the token's claims, or raise. Does NOT check single-use.

    Callers must additionally confirm the session has not already been redeemed —
    a valid signature says the token is authentic, not that it is still unspent.
    """
    if not token or token.count(".") != 4:
        raise OnboardingTokenError("malformed onboarding token")

    version, session_id, expires_raw, nonce, signature = token.split(".")
    if version != _TOKEN_VERSION:
        raise OnboardingTokenError(f"unsupported onboarding token version {version!r}")
    try:
        expires_at = int(expires_raw)
    except ValueError:
        raise OnboardingTokenError("malformed onboarding token expiry") from None

    # Signature before expiry: never let a caller distinguish "expired" from
    # "forged", and never parse claims we have not authenticated.
    if not hmac.compare_digest(signature, _sign(session_id, expires_at, nonce)):
        raise OnboardingTokenError("onboarding token signature does not verify")
    if expires_at < int(time.time()):
        raise OnboardingTokenError("onboarding token has expired")

    return OnboardingToken(
        session_id=session_id, expires_at=expires_at, nonce=nonce, value=token
    )


if __name__ == "__main__":
    # Offline self-check: round-trip, non-determinism, tamper and expiry.
    os.environ[SECRET_ENV] = "x" * 40
    minted = mint("sess-a", 600)
    assert verify(minted.value).session_id == "sess-a"
    assert looks_like_session_token(minted.value)
    assert not looks_like_session_token(secrets.token_urlsafe(32))
    assert mint("sess-a", 600).value != minted.value, "mint must never repeat"

    for bad in ("", "nope", minted.value[:-1] + ("0" if minted.value[-1] != "0" else "1")):
        try:
            verify(bad)
        except OnboardingTokenError:
            pass
        else:
            raise AssertionError(f"forged/malformed token accepted: {bad!r}")

    # A token whose session id claims to be another session must not verify —
    # the session id is inside the signed message.
    parts = minted.value.split(".")
    swapped = ".".join(["v1", "sess-b", parts[2], parts[3], parts[4]])
    try:
        verify(swapped)
    except OnboardingTokenError:
        pass
    else:
        raise AssertionError("session id is not covered by the signature")

    expired = mint("sess-c", MIN_TTL_SECONDS)
    object.__setattr__(expired, "expires_at", 1)
    forged_expiry = ".".join(["v1", "sess-c", "1", expired.nonce, _sign("sess-c", 1, expired.nonce)])
    try:
        verify(forged_expiry)
    except OnboardingTokenError as exc:
        assert "expired" in str(exc)
    else:
        raise AssertionError("expired token accepted")

    # A short secret must fail closed rather than sign with weak key material.
    os.environ[SECRET_ENV] = "short"
    assert not secret_is_configured()
    try:
        mint("sess-d")
    except OnboardingTokenError:
        pass
    else:
        raise AssertionError("minted a token without an adequate signing secret")
    print("onboarding_token self-check OK")
