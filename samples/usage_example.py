#!/usr/bin/env python3
"""Example usage of the magic-link login organ.

Loads the bundled sample LoginAttempts and prints the decision the organ would
make. Run: ``python samples/usage_example.py``
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from organ import decide  # noqa: E402

# The orchestrator passes the SECRET_KEY salt the stored code was hashed with.
CONTEXT = {"secret_salt": "test-secret-key", "max_attempts": 5, "session_ttl_minutes": 60}


def print_decision(title: str, result: dict) -> None:
    out = result["output"]
    print("=" * 60)
    print(title)
    print("=" * 60)
    print("Decision  : {0}".format(out["decision"]))
    print("Confidence: {0:.0%}".format(result["self_metric"]["confidence"]))
    print("Reason    : {0}".format(out["reason"]))
    print("Mutations : {0}".format(out["mutations"]))
    if out["session"]:
        print("Session   : {0}".format(out["session"]))
    print(result["rationale"])
    print()


def main() -> None:
    samples_dir = Path(__file__).parent
    for fname, title in [
        ("accept.json", "Valid code · issue session"),
        ("reject_wrong_code.json", "Wrong code"),
        ("reject_expired.json", "Expired code"),
        ("reject_no_code.json", "No code on file"),
        ("reject_locked_attempts.json", "Attempt budget exhausted"),
    ]:
        with open(samples_dir / fname) as f:
            state = json.load(f)
        print_decision(title, decide(state, CONTEXT))

    print_decision("Empty state (fail-safe → reject)", decide({}, {}))


if __name__ == "__main__":
    main()
