# organ-auth

A **pure decider organ** for magic-link / email-code login, per the orchestrator
[`CONTRACT.md`](https://github.com/Data-Flow-Advisory/orchestrator/blob/feat/drift-gate/CONTRACT.md)
and the connection standard
[`CONNECTORS.md`](https://github.com/Data-Flow-Advisory/orchestrator/blob/feat/drift-gate/CONNECTORS.md).

> Reabsorbed from discovery-engine `app/services/email_auth.py` (`verify_code`,
> `request_code`, `domain_allowed`) and `app/routes/auth.py` (the `verify()` →
> `login_user()` session-issuance path). The proven *logic* came across; the
> monolith *wiring* (Flask, SQLAlchemy, Gmail, `secrets`) stayed behind.

## The decision

> Given a submitted one-time code + the outstanding stored code record + the
> clock — **is this login valid, and if so, what Session do we issue?**

`decide(state, context)` validates the code (expiry, single-use, attempt budget,
salted-hash match) and on success returns a `Session` descriptor. It never acts:
the orchestrator owns the impure edges — fetching the stored `LoginCode` row,
generating & emailing the code, minting the real signed cookie, and applying the
**mutations the organ advises** (`consume_code`, `increment_attempts`).

Pure: no side effects, deterministic, stdlib-only (`hashlib`, `hmac`, `datetime`).
**Fail-safe to `reject`** on empty/malformed state — never a confident-wrong "yes".

## Ports (the Lego stud)

Per [`CONNECTORS.md`](https://github.com/Data-Flow-Advisory/orchestrator/blob/feat/drift-gate/CONNECTORS.md),
declared in [`ports.json`](ports.json):

| direction | name | type |
|-----------|------|------|
| input  | `login`   | `LoginAttempt` |
| output | `session` | `Session` |

`LoginAttempt` and `Session` are **proposed additions** to the shared vocabulary
([`types-proposed.json`](types-proposed.json)) — they describe an authentication
seam no existing type covers. They are submitted for review (new types are
reviewed, not minted freely) in this PR; merge into `orchestrator/types.json`
once approved.

## Input / output

`state.login` (a `LoginAttempt`; a bare top-level snapshot is also accepted):

```json
{
  "login": {
    "email": "ruth@example.com",
    "submitted_code": "482913",
    "now": "2026-06-11T10:05:00+00:00",
    "stored_code": {
      "code_hash": "aa2e36…",
      "expires_at": "2026-06-11T10:15:00+00:00",
      "attempts": 0,
      "consumed": false,
      "created_at": "2026-06-11T10:00:00+00:00"
    }
  }
}
```

`context` (policy + secret):

| key | default | meaning |
|-----|---------|---------|
| `secret_salt` | `""` | the SECRET_KEY salt `stored_code.code_hash` was produced with |
| `max_attempts` | `5` | `LOGIN_CODE_MAX_ATTEMPTS` |
| `hash_algorithm` | `sha256` | how the stored hash was computed |
| `session_ttl_minutes` | `43200` | issued-session lifetime (~30d, `remember=True`) |
| `session_source` | `magic_link` | recorded on the Session |

Output:

```json
{
  "output": {
    "decision": "accept",
    "session": {"email": "ruth@example.com", "authenticated": true,
                "issued_at": "...", "expires_at": "...", "source": "magic_link"},
    "reason": "Code verified; session issued.",
    "mutations": [{"op": "consume_code", "email": "ruth@example.com"}]
  },
  "rationale": "Submitted code matched the outstanding … stored code …",
  "self_metric": {"confidence": 0.97, "attempts_used": 0}
}
```

On reject, `session` is `null`, `reason` carries the user-facing copy, and
`mutations` carries the advice (`increment_attempts` on a mismatch,
`consume_code` when the attempt budget is exhausted).

## Bonus pure helpers (request edge)

Reabsorbed alongside `decide()`, for the orchestrator's "issue a code" edge:

- `domain_allowed(email, allowed_domains)` — config allow-list (`"*"` = any).
- `evaluate_request(email, recent_code_times, now, context)` — the
  outstanding-codes rate limit → `{allow, reason, wait_minutes}`.

## Run it

```bash
# stdin or ORGAN_INPUT (a FILE PATH) — CONTRACT entrypoint
echo '{"state": {...}, "context": {...}}' | python organ.py
ORGAN_INPUT=samples/accept.json python organ.py     # bare-state snapshot also accepted

python samples/usage_example.py     # walk the bundled samples
python -m pytest test_organ.py -v   # tests
```

## Conformance

The [conformance Action](.github/workflows/conformance.yml) asserts the contract on
Python 3.9–3.12: signature, fail-safe-reject on empty state, sample decisions,
the `ORGAN_INPUT` file-path entrypoint, the `ports.json` ↔ vocabulary check,
determinism, no input mutation, and stdlib-only imports.
