"""Magic-link / email-code login organ — pure decider per orchestrator CONTRACT.

Reabsorbed from discovery-engine ``app/services/email_auth.py`` (``verify_code`` /
``request_code`` / ``domain_allowed``) and ``app/routes/auth.py`` (the
``verify()`` → ``login_user()`` session-issuance path). Those modules braid a
genuinely *pure* decision together with side-effecting I/O: a DB lookup of the
outstanding ``LoginCode`` row, a Gmail send, a ``secrets``-random code, and a
``db.session.commit`` that consumes the code and issues a Flask-Login session.

This organ isolates the **decision** and leaves the monolith wiring behind. The
orchestrator owns the impure edges — fetching the stored code record, generating
& emailing the code, minting the actual signed session cookie, and applying the
mutations this organ *advises* (consume the code, increment the attempt counter).
The organ is handed a plain snapshot and decides:

    given a submitted code + the outstanding stored code record + the clock,
    is this login valid — and if so, what Session do we issue?

Pure: no side effects, deterministic, stdlib-only. Fail-safe to *reject* (the
conservative verdict) on empty/malformed state — never a confident-wrong "yes".

Connection standard (CONNECTORS.md): this organ's port shape is
    inputs : [{"name": "login",   "type": "LoginAttempt"}]
    outputs: [{"name": "session", "type": "Session"}]
``LoginAttempt`` and ``Session`` are proposed additions to the shared
vocabulary — see ``types-proposed.json`` and the PR body.

Signature: decide(state: dict, context: dict) -> dict
Returns: {output, rationale, self_metric} with self_metric.confidence required.
"""
import hashlib
import hmac
import json
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

# Policy defaults — mirror discovery-engine ``current_app.config`` keys.
_DEFAULTS = {
    "max_attempts": 5,            # LOGIN_CODE_MAX_ATTEMPTS
    "hash_algorithm": "sha256",   # how stored_code.code_hash was produced
    "secret_salt": "",            # SECRET_KEY salt folded into the hash
    "session_ttl_minutes": 43200,  # issued-session lifetime (30d ~ remember=True)
    "session_source": "magic_link",
    # request-edge policy (consumed by evaluate_request, not decide):
    "code_ttl_minutes": 15,       # LOGIN_CODE_TTL_MIN
    "max_outstanding_codes": 3,   # rate-limit ceiling per email in the TTL window
}


def decide(state: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Validate a submitted login code and decide whether to issue a Session.

    Args:
        state: snapshot of the login world. Recognised under the ``login`` port
            (a ``LoginAttempt``); a bare snapshot at the top level is also
            accepted for convenience. Keys:
                ``email``           the email the code was sent to (lower-cased).
                ``submitted_code``  the plaintext code the user typed.
                ``stored_code``     the outstanding LoginCode row the orchestrator
                                    fetched, or null/absent if none on file:
                                        {code_hash, expires_at, attempts,
                                         consumed, created_at}
                ``now``             ISO-8601 "now" (tz-aware or naive-UTC).
        context: policy + secrets (any subset of ``_DEFAULTS``). ``secret_salt``
            is the SECRET_KEY the orchestrator hashed the stored code with.

    Returns:
        {
            "output": {
                "decision": "accept" | "reject",
                "session": Session | null,   # the wired output port
                "reason": str,               # user-facing copy
                "mutations": [ {op, ...} ],  # advice for the orchestrator to apply
            },
            "rationale": str,
            "self_metric": {"confidence": 0.0-1.0, ...},
        }
    """
    cfg = _resolve_settings(context)
    login = _resolve_login(state)

    if not login:
        return _reject(
            "Please enter the code we emailed you.",
            "No login attempt present in state; nothing to validate.",
            confidence=0.2,
        )

    email = _norm_email(login.get("email"))
    submitted = (login.get("submitted_code") or "").strip()

    if not email or not submitted:
        return _reject(
            "Please enter the code we emailed you.",
            "Login attempt is missing an email and/or submitted code.",
            confidence=0.3,
        )

    stored = login.get("stored_code")
    if not isinstance(stored, dict) or not stored:
        return _reject(
            "No code on file. Please request a new one.",
            "No outstanding stored code record was supplied for this email.",
            confidence=0.85,
        )

    now = _parse_iso(login.get("now"))
    if now is None:
        return _reject(
            "We couldn't verify the code right now. Please try again.",
            "State has no parseable 'now'; cannot evaluate expiry.",
            confidence=0.2,
        )

    if bool(stored.get("consumed")):
        return _reject(
            "That code has already been used. Please request a new one.",
            "Stored code is already consumed; replay refused.",
            confidence=0.9,
        )

    expires_at = _parse_iso(stored.get("expires_at"))
    if expires_at is not None and expires_at < now:
        return _reject(
            "That code has expired. Please request a new one.",
            "Stored code's expires_at is in the past relative to now.",
            confidence=0.92,
        )

    attempts = _coerce_int(stored.get("attempts"), 0)
    max_attempts = cfg["max_attempts"]
    if attempts >= max_attempts:
        return _reject(
            "Too many wrong attempts. Please request a new code.",
            "Attempt counter at/above the max before this try; locking the code.",
            confidence=0.9,
            mutations=[{"op": "consume_code", "email": email}],
        )

    stored_hash = stored.get("code_hash") or ""
    computed = _hash_code(cfg["secret_salt"], submitted, cfg["hash_algorithm"])
    if not _hash_match(computed, stored_hash):
        next_attempts = attempts + 1
        remaining = max_attempts - next_attempts
        if remaining <= 0:
            return _reject(
                "Too many wrong attempts. Please request a new code.",
                "Code mismatch exhausted the attempt budget; locking the code.",
                confidence=0.9,
                mutations=[{"op": "consume_code", "email": email}],
            )
        unit = "attempt" if remaining == 1 else "attempts"
        return _reject(
            "That code didn't match. {0} {1} left.".format(remaining, unit),
            "Submitted code's hash did not match the stored hash.",
            confidence=0.88,
            mutations=[{"op": "increment_attempts", "email": email}],
        )

    # Success — issue a Session and advise consuming every outstanding code.
    issued_at = now
    ttl = timedelta(minutes=cfg["session_ttl_minutes"])
    session = {
        "email": email,
        "authenticated": True,
        "issued_at": _iso(issued_at),
        "expires_at": _iso(issued_at + ttl),
        "source": cfg["session_source"],
    }
    return {
        "output": {
            "decision": "accept",
            "session": session,
            "reason": "Code verified; session issued.",
            "mutations": [{"op": "consume_code", "email": email}],
        },
        "rationale": (
            "Submitted code matched the outstanding (unconsumed, unexpired, "
            "under-attempt-limit) stored code for {0}; issuing a {1}-minute "
            "session.".format(email, cfg["session_ttl_minutes"])
        ),
        "self_metric": {"confidence": 0.97, "attempts_used": attempts},
    }


# ---------------------------------------------------------------------------
# Reject helper — keeps the conservative-verdict shape uniform.
# ---------------------------------------------------------------------------

def _reject(
    reason: str,
    rationale: str,
    confidence: float,
    mutations: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    return {
        "output": {
            "decision": "reject",
            "session": None,
            "reason": reason,
            "mutations": mutations or [],
        },
        "rationale": rationale,
        "self_metric": {"confidence": round(confidence, 2)},
    }


# ---------------------------------------------------------------------------
# Settings / input resolution
# ---------------------------------------------------------------------------

def _resolve_settings(context: Dict[str, Any]) -> Dict[str, Any]:
    """Merge caller context over the policy defaults, coercing types."""
    ctx = context or {}
    cfg = dict(_DEFAULTS)
    for key in _DEFAULTS:
        if key in ctx and ctx[key] is not None:
            cfg[key] = ctx[key]

    cfg["max_attempts"] = max(1, _coerce_int(cfg["max_attempts"], _DEFAULTS["max_attempts"]))
    cfg["session_ttl_minutes"] = max(
        1, _coerce_int(cfg["session_ttl_minutes"], _DEFAULTS["session_ttl_minutes"])
    )
    cfg["code_ttl_minutes"] = max(
        1, _coerce_int(cfg["code_ttl_minutes"], _DEFAULTS["code_ttl_minutes"])
    )
    cfg["max_outstanding_codes"] = max(
        1, _coerce_int(cfg["max_outstanding_codes"], _DEFAULTS["max_outstanding_codes"])
    )
    if not isinstance(cfg["secret_salt"], str):
        cfg["secret_salt"] = str(cfg["secret_salt"])
    if cfg["hash_algorithm"] not in hashlib.algorithms_available:
        cfg["hash_algorithm"] = _DEFAULTS["hash_algorithm"]
    return cfg


def _resolve_login(state: Dict[str, Any]) -> Dict[str, Any]:
    """Read the ``login`` input port; tolerate a bare top-level snapshot."""
    if not isinstance(state, dict) or not state:
        return {}
    login = state.get("login")
    if isinstance(login, dict):
        return login
    # Convenience: accept a flat snapshot that *is* the LoginAttempt.
    if "submitted_code" in state or "stored_code" in state:
        return state
    return {}


# ---------------------------------------------------------------------------
# Hashing (pure port of email_auth._hash_code) — constant-time compare.
# ---------------------------------------------------------------------------

def _hash_code(salt: str, code: str, algorithm: str = "sha256") -> str:
    """Salted hash of a code: ``H(salt + ':' + code)``.

    Mirrors discovery-engine ``email_auth._hash_code`` so a hash produced by the
    monolith verifies identically here. Pure & deterministic.
    """
    h = hashlib.new(algorithm)
    h.update((str(salt) + ":" + str(code)).encode("utf-8"))
    return h.hexdigest()


def _hash_match(computed: str, stored: str) -> bool:
    """Constant-time hex-digest comparison (avoids a timing side-channel)."""
    if not computed or not stored:
        return False
    return hmac.compare_digest(str(computed), str(stored))


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _parse_iso(value: Any) -> Optional[datetime]:
    """Parse an ISO-8601 string to a tz-aware UTC datetime, or None."""
    if not isinstance(value, str) or not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        # Naive timestamps are UTC (discovery-engine stores naive-UTC — _time.py).
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _iso(dt_utc: datetime) -> str:
    return dt_utc.isoformat()


def _norm_email(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip().lower()


def _coerce_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Request-edge pure helpers (reabsorbed from email_auth, exposed for the
# orchestrator's "issue a code" edge). Not part of the decide() port, but pure
# and tested — the orchestrator wires them ahead of generating/emailing a code.
# ---------------------------------------------------------------------------

def domain_allowed(email: str, allowed_domains: Optional[List[str]] = None) -> bool:
    """Config-driven allow-list check (port of email_auth.domain_allowed).

    Empty list or a ``"*"`` wildcard allows any domain. Pure.
    """
    allowed = [str(d).lower() for d in (allowed_domains or [])]
    if not allowed or "*" in allowed:
        return True
    if not isinstance(email, str) or "@" not in email:
        return False
    return email.lower().rsplit("@", 1)[1] in allowed


def evaluate_request(
    email: str,
    recent_code_times: Optional[List[str]],
    now: Any,
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Rate-limit decision for issuing a fresh login code (port of the
    ``request_code`` outstanding-codes guard). Pure.

    Args:
        email: the requesting email.
        recent_code_times: ISO timestamps of codes already issued to this email
            inside the TTL window (orchestrator-fetched).
        now: ISO "now".
        context: policy (``code_ttl_minutes``, ``max_outstanding_codes``).

    Returns {allow: bool, reason: str|None, wait_minutes: int}.
    """
    cfg = _resolve_settings(context or {})
    norm = _norm_email(email)
    if not norm or "@" not in norm:
        return {"allow": False, "reason": "Please enter a valid email address.", "wait_minutes": 0}

    now_dt = _parse_iso(now)
    times = sorted(
        t for t in (_parse_iso(x) for x in (recent_code_times or [])) if t is not None
    )
    if now_dt is None or len(times) < cfg["max_outstanding_codes"]:
        return {"allow": True, "reason": None, "wait_minutes": 0}

    # Exact wait = time until the oldest in-window code ages out (ceil, floor 1).
    oldest = times[0]
    ttl = timedelta(minutes=cfg["code_ttl_minutes"])
    seconds_remaining = ((oldest + ttl) - now_dt).total_seconds()
    wait_minutes = max(1, _ceil_minutes(seconds_remaining))
    unit = "minute" if wait_minutes == 1 else "minutes"
    return {
        "allow": False,
        "reason": (
            "Too many codes requested recently. Please wait {0} {1} before "
            "requesting another code.".format(wait_minutes, unit)
        ),
        "wait_minutes": wait_minutes,
    }


def _ceil_minutes(seconds: float) -> int:
    if seconds <= 0:
        return 0
    return int(seconds // 60) + (1 if seconds % 60 else 0)


# ---------------------------------------------------------------------------
# CLI entrypoint — read {state, context} from ORGAN_INPUT file or stdin.
# (CONTRACT.md: input is one JSON object; ORGAN_INPUT names a *file path*.)
# ---------------------------------------------------------------------------

def _read_input() -> Dict[str, Any]:
    import os
    path = os.environ.get("ORGAN_INPUT")
    if path:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return json.load(sys.stdin)


def main() -> int:
    payload = _read_input()
    if isinstance(payload, dict) and "state" in payload:
        state = payload.get("state") or {}
        context = payload.get("context") or {}
    else:
        # A bare LoginAttempt / state snapshot was supplied directly.
        state = payload if isinstance(payload, dict) else {}
        context = {}
    result = decide(state, context)
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
